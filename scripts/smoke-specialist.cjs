// Optional real-model check. No fixture server or simulated model responses.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const connectAppMcp=require('./mcp-test-client.cjs');
const {showPanel,revealDetails,showAnalysisSection}=require('./ui-test-navigation.cjs');
const {chromium}=require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
(async()=>{
  const root=process.env.QUIXI_SMOKE_ROOT;
  assert(root && process.env.REA_STUDIO_PROVIDER_CONFIG,'Set the fixture path and the provider config to use');
  const providers=JSON.parse(fs.readFileSync(process.env.REA_STUDIO_PROVIDER_CONFIG,'utf8'));
  const provider=providers.providers.find(p=>p.id===(process.env.REA_STUDIO_PROVIDER_ID || 'custom'));assert(provider);
  const model=process.env.REA_STUDIO_SPECIALIST_MODEL;assert(model,'Choose an actually served LLM4Decompile model');
  const browser=await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  const page=browser.contexts()[0].pages().find(p=>p.url().includes('app.localhost/playground'));assert(page);
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const native=(route,data={})=>page.evaluate(async({route,data})=>{const r=await fetch('/api/quixi/'+route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const v=await r.json();if(!r.ok)throw Error(v.error || String(r.status));return v;},{route,data});
  const pg=(route,data={})=>native('playground/'+route,data);
  let mcp;
  try{
    await page.reload();await page.locator('#connection').filter({hasText:'Connected'}).waitFor();
    const project=await pg('project',{path:root});
    await native('providers/save',{providerId:'custom',baseUrl:provider.baseUrl,apiKey:provider.apiKeyRaw || '',selectedModel:provider.selectedModel,completeOnboarding:true});
    const models=await pg('decompile/models',{provider:'custom'});assert(models.models.includes(model));
    await pg('decompile/configure',{settings:{enabled:true,provider:'custom',model,profile:'llm4-ref',maxTokens:512}});
    await pg('rea/select',{path:path.join(root,'quixi-fixture.exe')});
    await pg('rea/connect');
    const opened=await pg('rea/tool',{tool:'open_binary',arguments:{path:path.join(root,'quixi-fixture.exe'),provider_id:'ghidra'}});assert.equal(opened.failed,false);
    const original=await pg('rea/tool',{tool:'procedure_pseudo_code',arguments:{procedure:'quixi_add'}});assert.equal(original.failed,false);
    const input=await pg('decompile/input',{recordId:original.id});assert.match(input.input,/quixi_add/);
    console.log('Specialist check: original function decompiled with real Ghidra');
    const before=await page.evaluate(async()=>{const r=await fetch('/api/quixi/playground/state');return (await r.json()).providers;});
    mcp=await connectAppMcp(page);
    assert.equal((await mcp.call('studio_decompile_status')).settings.model,model);
    const result=await mcp.call('studio_decompile_assist',{recordId:original.id});assert.equal(result.failed,false,JSON.stringify(result.response));assert.equal(result.kind,'model-suggestion');
    const generated=result.response.structuredContent;assert.match(generated.decompiled_code,/quixi_add/);assert.equal(generated.verified,false);assert.equal(result.provenance.sourceRecordId,original.id);
    assert.equal(result.provenance.input,input.input);
    fs.writeFileSync(path.join(root,'llm4-suggestion.c'),generated.decompiled_code);
    const after=await page.evaluate(async()=>{const r=await fetch('/api/quixi/playground/state');return (await r.json()).providers;});
    assert.equal(after.activeModel,before.activeModel);assert.equal(after.activeProvider,before.activeProvider);
    const status=await pg('decompile/status');assert.equal(status.connected,true);
    await page.locator('[data-view=analysis]').click();
    await page.evaluate(async id=>{await refreshState();await loadDecompileSettings();await loadAnalysisHistory();renderEvidence(await pg('rea/evidence',{id}));await refreshConnectionBadges();},original.id);
    await showAnalysisSection(page,'analysis-advanced-tools');await revealDetails(page,'#decompile-prepare');
    assert.match(await page.locator('#decompile-connection').textContent(),/^Connected/);
    // The Agent model is the driver; the helper is a tool it calls.
    assert.match(await page.locator('#helper-status').textContent(),/^On/);
    await showPanel(page,'settings');await page.locator('#model').selectOption('custom::'+provider.selectedModel);
    await showAnalysisSection(page,'analysis-advanced-tools');await revealDetails(page,'#decompile-prepare');await page.locator('#decompile-prepare').click();
    await page.waitForFunction(()=>document.getElementById('task').value.includes('decompile_assist'));
    assert.match(await page.locator('#task').inputValue(),/decompile_assist/);
    assert.equal(await page.locator('#model').inputValue(),'custom::'+provider.selectedModel);
    assert.equal(await page.locator('#mode').inputValue(),'ask');
    if(process.env.REA_STUDIO_TEST_DRIVER==='1'){
      const run=await pg('run',{project:project.id,model:provider.selectedModel,mode:'ask',reaEnabled:true,prompt:`Use exactly this first action: {"action":"decompile_assist","recordId":"${original.id}"}. After receiving its result, return {"action":"done","summary":"Specialist suggestion received; compilation and behaviour are unverified."}. Do not claim that tests passed.`});
      let final;
      for(let i=0;i<120;i++){
        const state=await page.evaluate(async()=>{const r=await fetch('/api/quixi/playground/state');return r.json();});
        final=state.runs.find(r=>r.id===run.id);if(final && !['running','stopping'].includes(final.status))break;
        await new Promise(resolve=>setTimeout(resolve,2000));
      }
      assert.equal(final?.status,'completed',final?.reply);
      assert(final.events.some(e=>e.kind==='decompile_assist' && e.detail.failed===false),'Driving model must actually call the specialist');
      console.log('Specialist check: a separate real driving model called the specialist');
    }
    await showAnalysisSection(page,'analysis-advanced-tools');await revealDetails(page,'#decompile-settings');await page.evaluate(()=>refreshConnectionBadges());
    await page.screenshot({path:path.join(root,'decompilation-assistant.png'),fullPage:true});
    // Changing endpoint settings invalidates an earlier successful connection.
    await native('providers/save',{providerId:'custom',baseUrl:provider.baseUrl,apiKey:provider.apiKeyRaw || '',selectedModel:provider.selectedModel,completeOnboarding:true});
    assert.equal((await pg('decompile/status')).connected,false);
    await page.evaluate(()=>refreshConnectionBadges());
    assert(!String(await page.locator('#decompile-connection').textContent()).startsWith('Connected'));
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({passed:true,specialist:model,driver:provider.selectedModel,sourceRecord:original.id,suggestionRecord:result.id,complete:generated.complete,code:generated.decompiled_code,jsErrors:errors}));
  }finally{if(mcp)await mcp.close();await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
