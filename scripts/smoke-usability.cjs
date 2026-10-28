// Real UI regression for progressive disclosure; run alone in an isolated WebView profile.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {performance} = require('node:perf_hooks');
const {chromium} = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
const {version} = require('./version.cjs');
const {showPanel, revealDetails, showAnalysisSection} = require('./ui-test-navigation.cjs');
// Frozen pre-simplification DOM inventory: reading the new markup at runtime would not detect removals.
const preservedIds = [
  "connection", "theme", "mcp-settings", "providers", "explorer-toggle", "project-name", "project-path", "host",
  "open-project", "settings-toggle", "explorer", "refresh", "project", "received-code", "received-code-note", "received-code-open",
  "received-code-dismiss", "filter", "new-file", "files", "run-count", "run-filter", "runs", "dirty",
  "change-count", "new-run", "error", "view-overview", "welcome", "run-detail", "run-model", "run-title",
  "run-status", "run-continue", "run-parent", "run-approval", "run-approval-title", "approval-command", "approval-detail", "approval-reason",
  "approval-approve", "approval-deny", "reply", "run-changes-panel", "run-changes-title", "run-changes-count", "run-revert-all", "run-changes",
  "run-revert-confirm", "run-revert-title", "run-revert-skipped", "run-revert-force", "run-revert-cancel", "run-changes-message", "run-diff-title", "run-diff",
  "run-diff-more", "view-code", "editor-path", "save", "disk-bar", "disk-note", "disk-reload", "disk-keep",
  "disk-diff", "disk-diff-output", "lines", "editor", "file-stats", "view-changes", "refresh-diff", "changes-note",
  "changed-files", "discard-confirm", "discard-title", "discard-note", "discard-approve", "discard-cancel", "commit-form", "commit-message",
  "commit", "commit-output", "diff-title", "diff", "diff-more", "view-analysis", "re-guide-toggle", "toolchain-open",
  "rea-connect", "re-stages", "re-next", "artifact-name", "artifact-path", "artifact-file", "artifact-folder", "artifact-set-path",
  "analysis-source", "analysis-sources-refresh", "analysis-connections", "analysis-source-note", "decompile-settings", "decompile-connection", "decompile-summary", "decompile-setup",
  "decompile-input-load", "decompile-input-source", "decompile-input", "decompile-run", "decompile-prepare", "decompile-message", "ida-panel", "ida-status",
  "ida-session", "ida-setup", "ida-enable-headless", "ida-disable", "ida-url", "ida-enable-attached", "ida-open", "ida-close",
  "ida-annotations", "ida-form", "ida-tool", "ida-description", "ida-blocked", "ida-preflight", "ida-arguments", "ida-schema",
  "ida-run", "ida-register-rea", "ida-restore-rea", "ida-message", "external-analysis", "source-open", "source-import", "source-docs",
  "debugger-panel", "debugger-status", "debugger-toggle", "debugger-setup", "debugger-cmdline", "debugger-start", "debugger-sessions", "debugger-session-pid",
  "debugger-attach", "debugger-session-output", "debugger-form", "debugger-tool", "debugger-description", "debugger-arguments", "debugger-schema", "debugger-run",
  "reconstruction-scope", "reconstruction-goal", "reconstruction-observations", "reconstruction-destination", "reconstruction-plan", "reconstruction-dossier", "reconstruction-analyse", "reconstruction-build",
  "reconstruction-export", "oracle-run", "oracle-retry", "oracle-stop", "oracle-consent", "oracle-consent-title", "oracle-consent-note", "oracle-consent-sha",
  "oracle-consent-cases", "oracle-approve", "oracle-cancel", "oracle-result", "reconstruction-status", "rea-source-controls", "rea-runtime", "rea-provider",
  "rea-health", "rea-heap", "rea-startup-timeout", "rea-call-timeout", "rea-runtime-info", "rea-runtime-save", "rea-runtime-message", "inv-panel",
  "inv-name", "inv-targets", "inv-add-selected", "inv-add-history", "inv-create", "inv-select", "inv-refresh", "inv-check",
  "inv-export", "inv-delete", "inv-summary", "inv-open-manifest", "inv-rows", "inv-status", "rea-form", "rea-search",
  "rea-tool", "rea-description", "rea-availability", "rea-preflight", "rea-inputs", "rea-validation", "rea-arguments", "rea-schema",
  "rea-run", "rea-close", "rea-use", "rea-export", "re-prompt", "artifact-inventory-count", "artifact-inventory", "history-target",
  "history-tool", "rea-record", "evidence-summary", "code-toolbar", "code-back", "code-forward", "code-function", "code-rename",
  "code-comment", "code-note", "recovered-code", "evidence-raw", "evidence-raw-summary", "rea-output", "console", "event-count",
  "console-expand", "console-activity", "console-terminal", "terminal-note", "terminal-output", "terminal-form", "terminal-cwd", "terminal-command",
  "terminal-stop", "terminal-send", "task-form", "continue-chip", "continue-label", "continue-clear", "task", "composer-hint",
  "confirm-commands", "max-steps", "stop", "start", "settings", "models-title", "configure", "model",
  "helper-status", "helper-setup", "models-explainer", "models-diagram", "mode", "access-note", "execution-host", "execution-detail",
  "rea-badge", "rea-enabled", "show-analysis", "open-bench", "status", "branch", "selected-model", "provider-dialog",
  "provider-form", "provider-title", "close-provider", "connection-list", "connection-add", "connection-editor-title", "provider-id", "base-url",
  "api-key", "provider-env", "model-id", "provider-models", "provider-context-window", "provider-message", "detect-local", "test-provider",
  "helper-dialog", "helper-title", "helper-close", "decompile-provider", "helper-connections", "decompile-provider-note", "decompile-model", "decompile-model-options",
  "decompile-models", "decompile-profile-note", "decompile-profile", "decompile-max-tokens", "helper-dialog-status", "decompile-disable", "decompile-save", "helper-message",
  "native-close-dialog", "native-close-title", "native-close-note", "native-close-error", "native-close-cancel", "native-close-discard", "native-close-save", "text-dialog",
  "text-title", "text-label", "text-value", "toolchain-dialog", "toolchain-close", "toolchain-refresh", "rea-restart", "toolchain-list",
  "workflow-guide", "workflow-read", "workflow-next", "workflow-content", "mcp-dialog", "mcp-close", "mcp-status", "mcp-active",
  "mcp-port", "mcp-url", "mcp-toggle", "mcp-config", "mcp-rotate", "mcp-config-output", "mcp-message", "mcp-events",
  "classic-open", "classic-configure",
];
const report = {version:1,appVersion:version,status:'running',startedAt:new Date().toISOString(),checks:[],layouts:[],screenshots:[],jsErrors:[],
  scope:'Actual keyboard/navigation, responsive geometry, live REA catalog/manual JSON execution and saved evidence. No model completion or reconstructed-program equivalence claim.'};
const started=performance.now(),hash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
let browser,page,native,output,project,investigation,opened=false,preferences;
async function main(){
  const fixtureRoot=process.env.QUIXI_SMOKE_ROOT,profile=process.env.REA_STUDIO_TEST_DATA;
  assert(fixtureRoot && profile,'Set dedicated QUIXI_SMOKE_ROOT and REA_STUDIO_TEST_DATA');
  assert(!/(^|[\\/])\.quixi([\\/]|$)/i.test(path.resolve(profile)),'Use an isolated test profile');
  const target=path.join(fixtureRoot,'quixi-fixture.exe');assert(fs.statSync(target).isFile());const sha256=hash(target);
  const workspace=path.join(path.dirname(fixtureRoot),'usability-'+crypto.randomUUID());fs.mkdirSync(workspace);
  fs.writeFileSync(path.join(workspace,'README.md'),'# Usability fixture\nRead-only UI navigation.\n');
  output=path.resolve(process.env.REA_STUDIO_USABILITY_REPORT || path.join(workspace,'usability-report.json'));fs.mkdirSync(path.dirname(output),{recursive:true});
  report.workspace=workspace;report.target={path:target,sha256};
  browser=await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9325');
  page=browser.contexts()[0].pages().find(p=>p.url().includes('app.localhost/playground'));assert(page);
  page.setDefaultTimeout(30000);page.on('pageerror',e=>report.jsErrors.push(e.message));
  native=(route,data={})=>page.evaluate(async({route,data})=>{const r=await fetch('/api/quixi/playground/'+route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const v=await r.json();if(!r.ok)throw Error(v.error || String(r.status));return v;},{route,data});
  await page.reload();await ready();await page.setViewportSize({width:1440,height:920});
  assert.equal(await page.title(),'REA Studio V'+version+' · Coding & Reverse Engineering');
  preferences=await page.evaluate(()=>Object.fromEntries(['rea.ui.explorer','rea.ui.settings','rea.ui.expert'].map(k=>[k,localStorage.getItem(k)])));
  const missing=await page.evaluate(ids=>ids.filter(id=>document.querySelectorAll('[id="'+id+'"]').length!==1),preservedIds);
  assert.deepEqual(missing,[],'Original controls were removed or duplicated');
  report.checks.push({name:'all-original-control-ids-preserved',status:'passed',count:preservedIds.length});
  project=await native('project',{path:workspace});await native('rea/select',{project:project.id,path:target});
  await page.reload();await ready();await showPanel(page,'explorer');await page.locator('#project').selectOption(project.id);
  await page.locator('.file-row[title="README.md"]').click();
  await page.waitForFunction(()=>document.getElementById('editor').value.includes('Read-only UI navigation.'));
  await panel('explorer',false);await panel('settings',false);
  for(const id of ['explorer','settings']) assert.equal(await page.locator('#'+id+'-toggle').getAttribute('aria-controls'),id);
  await page.locator('#explorer-toggle').focus();await page.keyboard.press('Enter');await checkPanel('explorer',true);
  await page.reload();await ready();await checkPanel('explorer',true);await checkPanel('settings',false);
  await page.locator('#explorer-toggle').focus();await page.keyboard.press('Space');await checkPanel('explorer',false);
  await page.locator('#settings-toggle').focus();await page.keyboard.press('Space');await checkPanel('settings',true);
  await page.reload();await ready();await checkPanel('explorer',false);await checkPanel('settings',true);
  await panel('settings',false);await page.locator('#explorer-toggle').focus();
  for(let i=0;i<24;i++){await page.keyboard.press('Tab');await focusIsVisible();assert.equal(await page.evaluate(()=>!!document.activeElement.closest('#explorer,#settings')),false,'Hidden sidebar received keyboard focus');}
  report.checks.push({name:'keyboard-sidebar-operation-and-reload-persistence',status:'passed'});
  await page.locator('[data-view=overview]').click();await page.locator('#task-context').click();await checkPanel('settings',true);
  await page.locator('#mode').selectOption('code');assert.match(await page.locator('#task-context').textContent(),/Edit & run/);
  await panel('settings',false);await layout('desktop-default',['#explorer-toggle','#settings-toggle','#task-context']);
  await showAnalysisSection(page,'analysis-advanced-tools');await revealDetails(page,'#rea-runtime');await page.locator('#rea-runtime').selectOption('bundled');
  await page.waitForFunction(()=>document.getElementById('rea-badge').textContent==='Connected',null,{timeout:120000});
  const catalog=await native('rea/connect',{project:project.id,mode:'bundled'});assert(catalog.tools.length>0);
  await showAnalysisSection(page,'analysis-workspace');await page.locator('#rea-search').fill('');
  const visibleTools=await page.locator('#rea-tool option').evaluateAll(options=>options.map(o=>o.value).filter(Boolean).sort());
  assert.deepEqual(visibleTools,catalog.tools.map(t=>t.name).sort(),'Simplified view must retain the entire live tool catalog');
  await expert(false);await page.locator('[data-rea-tool=open_binary]').click();
  await page.waitForFunction(()=>document.getElementById('rea-tool').value==='open_binary');
  assert.equal(await page.locator('#rea-inputs input').count(),0);
  const presetFocus=await page.locator('#rea-run').isDisabled()?'rea-arguments':'rea-run';
  await page.locator('#'+presetFocus).waitFor({state:'visible'});await focusIsVisible();
  assert.equal(await page.evaluate(()=>document.activeElement.id),presetFocus,'Preset must focus either the runnable action or required manual arguments');
  const openedRecord=await runSelected('open_binary');opened=true;assert.equal(openedRecord.failed,false,JSON.stringify(openedRecord.response));
  await showAnalysisSection(page,'analysis-workspace');await page.locator('[data-rea-tool=search_strings]').click();
  await revealDetails(page,'#rea-description');
  assert.equal(await page.locator('#rea-description').textContent(),catalog.tools.find(t=>t.name==='search_strings').description,'Full live tool documentation was lost');
  assert((await page.locator('#rea-tool-summary').textContent()).trim().length>0,'Concise tool guidance is empty');
  await page.locator('#rea-tool-help > summary').click();
  report.checks.push({name:'full-live-tool-description-accessible',status:'passed'});
  await page.locator('#rea-input-pattern').waitFor({state:'visible'});await expert(false);
  await page.locator('#analysis-expert-toggle').focus();await page.keyboard.press('Space');
  await page.locator('#rea-arguments').waitFor({state:'visible'});assert.equal(await page.locator('#analysis-expert-toggle').getAttribute('aria-pressed'),'true');
  const args={pattern:'quixi',detail:'summary'};
  await page.locator('#rea-arguments').fill(JSON.stringify(args));assert.equal(await page.locator('#rea-input-pattern').inputValue(),args.pattern);
  await expert(false);await expert(true);assert.deepEqual(JSON.parse(await page.locator('#rea-arguments').inputValue()),args,'Disclosure toggles lost manual arguments');
  await revealDetails(page,'#rea-schema');assert.deepEqual(JSON.parse(await page.locator('#rea-schema').textContent()),catalog.tools.find(t=>t.name==='search_strings').inputSchema);
  const before=new Set((await native('rea/inventory',{project:project.id})).records.map(r=>r.id));
  const record=await runSelected('search_strings');
  assert.equal(record.failed,false,JSON.stringify(record.response));assert(!before.has(record.id),'Manual run did not create new evidence');
  assert.deepEqual(record.arguments,args);assert.equal(path.resolve(record.target).toLowerCase(),path.resolve(target).toLowerCase());
  assert.equal(record.artifactIdentity?.status,'verified');assert.equal(record.artifactIdentity.sha256,sha256);
  assert.deepEqual(await native('rea/evidence',{project:project.id,id:record.id}),record);
  report.evidence={id:record.id,tool:record.tool,arguments:record.arguments,sha256};report.catalogCount=catalog.tools.length;
  report.checks.push({name:'complete-live-catalog-and-real-manual-json-run',status:'passed'});
  await page.reload();await ready();await showAnalysisSection(page,'analysis-workspace');
  assert.equal(await page.locator('#analysis-expert-toggle').getAttribute('aria-pressed'),'true');await page.locator('#rea-arguments').waitFor({state:'visible'});
  await showAnalysisSection(page,'analysis-evidence');await page.locator('#rea-record').selectOption(record.id);await revealDetails(page,'#rea-output');
  await page.waitForFunction(id=>{try{return JSON.parse(document.getElementById('rea-output').textContent).id===id;}catch{return false;}},record.id);
  assert.deepEqual(JSON.parse(await page.locator('#rea-output').textContent()),record);
  await showAnalysisSection(page,'inv-panel');await page.waitForFunction(()=>!QuixiInvestigations.busy);
  await page.locator('#inv-name').fill('Usability '+crypto.randomUUID());await page.locator('#inv-targets').fill(target);
  const creating=page.waitForResponse(r=>r.url().endsWith('/investigation/create')&&r.request().method()==='POST');await page.locator('#inv-create').click();
  const created=await creating;assert(created.ok());investigation=(await created.json()).investigation;
  await page.waitForFunction(()=>!QuixiInvestigations.busy);await page.locator('#inv-rows .investigation-artifact[data-status=current]').waitFor();
  await layout('desktop-analysis-advanced',['#inv-select','#inv-check','#inv-export']);
  await showAnalysisSection(page,'reconstruction-panel');await page.locator('#reconstruction-goal').fill('Recover the fixture addition behavior without modifying the original.');
  await page.locator('#reconstruction-analyse').click();
  await page.waitForFunction(()=>document.getElementById('task').value.startsWith('[Reconstruction brief]'));
  assert.equal(await page.locator('#task').isVisible(),true);assert.equal(await page.evaluate(()=>document.activeElement.id),'task');
  assert.match(await page.locator('#task-context').textContent(),/Read only/);
  report.checks.push({name:'evidence-investigation-rebuild-and-task-handoff-reachable',status:'passed'});
  await panel('explorer',false);await panel('settings',false);
  const desktopPreferences=await page.evaluate(()=>[localStorage.getItem('rea.ui.explorer'),localStorage.getItem('rea.ui.settings')]);
  for(const width of [1000,480]){
    await page.setViewportSize({width,height:width===480?900:920});await checkPanel('explorer',false);await checkPanel('settings',false);
    await page.locator('[data-view=analysis]').click();await expert(false);await showAnalysisSection(page,'analysis-workspace');
    await layout('width-'+width+'-default',['#artifact-set-path','#rea-tool','#rea-run']);
    await page.locator('#explorer-toggle').focus();await page.keyboard.press('Enter');await checkPanel('explorer',true);await checkPanel('settings',false);
    await layout('width-'+width+'-files',['#project','#filter']);
    await page.locator('#explorer-toggle').focus();await page.keyboard.press('Tab');
    for(let i=0;i<18;i++){await page.keyboard.press('Tab');await focusIsVisible();assert.equal(await page.evaluate(()=>document.activeElement.id==='explorer-toggle'||!!document.activeElement.closest('#explorer')),true,'Mobile focus escaped open Files overlay');}
    await page.locator('#settings-toggle').click();await checkPanel('settings',true);await checkPanel('explorer',false);
    await page.locator('#show-analysis').click();await checkPanel('settings',false);await page.locator('#view-analysis').waitFor({state:'visible'});await focusIsVisible();
    await showPanel(page,'explorer');
    await page.keyboard.press('Escape');await checkPanel('explorer',false);assert.equal(await page.evaluate(()=>document.activeElement.id),'explorer-toggle');
    await page.locator('#settings-toggle').focus();await page.keyboard.press('Space');await checkPanel('settings',true);await checkPanel('explorer',false);
    await layout('width-'+width+'-settings',['#model','#mode']);
    await page.locator('#panel-backdrop').click({position:{x:2,y:2}});await checkPanel('settings',false);assert.equal(await page.evaluate(()=>document.activeElement.id),'settings-toggle');
    await showAnalysisSection(page,'analysis-workspace');await expert(true);await revealDetails(page,'#rea-schema');
    await layout('width-'+width+'-advanced',['#rea-arguments','#rea-run']);
    await showAnalysisSection(page,'analysis-evidence');await layout('width-'+width+'-evidence',['#rea-record','#rea-use']);
    await showAnalysisSection(page,'inv-panel');await page.waitForFunction(()=>!QuixiInvestigations.busy);await layout('width-'+width+'-investigation',['#inv-select','#inv-check']);
    await showAnalysisSection(page,'reconstruction-panel');await layout('width-'+width+'-rebuild',['#reconstruction-scope','#reconstruction-goal','#reconstruction-analyse']);
    await showAnalysisSection(page,'analysis-advanced-tools');await revealDetails(page,'#ida-arguments');await layout('width-'+width+'-bridge',['#ida-tool','#ida-arguments']);
    assert.deepEqual(await page.evaluate(()=>[localStorage.getItem('rea.ui.explorer'),localStorage.getItem('rea.ui.settings')]),desktopPreferences,'Mobile overlays changed desktop preferences');
  }
  await page.setViewportSize({width:1440,height:920});await checkPanel('explorer',false);await checkPanel('settings',false);
  await showAnalysisSection(page,'analysis-workspace');await expert(false);await layout('desktop-analysis-default',['#artifact-set-path','#rea-tool','#rea-run']);
  await expert(true);await revealDetails(page,'#rea-schema');await layout('desktop-analysis-expert',['#rea-arguments','#rea-run']);
  report.checks.push({name:'responsive-1440-1000-480-and-mobile-overlay-focus',status:'passed'});
  assert.equal(hash(target),sha256,'Original binary changed');assert.deepEqual(report.jsErrors,[]);
}
async function ready(){await page.locator('#connection').filter({hasText:'Connected'}).waitFor();await page.waitForFunction(()=>!!window.QuixiWorkflow);}
async function checkPanel(id,open){
  await page.waitForFunction(({id,open})=>document.getElementById(id+'-toggle').getAttribute('aria-expanded')===String(open)&&document.getElementById(id).inert===!open,{id,open});
  assert.equal(await page.locator('#'+id).isVisible(),open);
}
async function panel(id,open){if((await page.locator('#'+id+'-toggle').getAttribute('aria-expanded')==='true')!==open)await page.locator('#'+id+'-toggle').click();await checkPanel(id,open);}
async function expert(open){if((await page.locator('#analysis-expert-toggle').getAttribute('aria-pressed')==='true')!==open)await page.locator('#analysis-expert-toggle').click();await page.waitForFunction(open=>document.getElementById('rea-advanced').open===open,open);}
async function focusIsVisible(){
  const focused=await page.evaluate(()=>{const n=document.activeElement,r=n.getBoundingClientRect(),s=getComputedStyle(n),x=(Math.max(0,r.left)+Math.min(innerWidth,r.right))/2,y=(Math.max(0,r.top)+Math.min(innerHeight,r.bottom))/2,h=document.elementFromPoint(x,y);return{id:n.id,hidden:!!n.closest('[hidden],[inert]'),visibility:s.visibility,width:r.width,height:r.height,intersects:r.right>0&&r.bottom>0&&r.left<innerWidth&&r.top<innerHeight,hit:!!h&&(h===n||n.contains(h))};});
  assert(!focused.hidden&&focused.visibility==='visible'&&focused.width>0&&focused.height>0&&focused.intersects&&focused.hit,'Focus landed on an obscured or hidden control: '+JSON.stringify(focused));
}
async function runSelected(tool){
  const pending=page.waitForResponse(r=>r.url().endsWith('/rea/tool')&&r.request().method()==='POST'&&r.request().postDataJSON()?.tool===tool,{timeout:180000});
  await page.locator('#rea-run').click();const response=await pending;assert(response.ok());const record=await response.json();
  await page.waitForFunction(()=>!state.rea.operation&&!state.rea.connecting,null,{timeout:180000});return record;
}
async function layout(name,selectors){
  const geometry=await page.evaluate(()=>({width:innerWidth,height:innerHeight,documentWidth:document.documentElement.scrollWidth,bodyWidth:document.body.scrollWidth}));
  assert(geometry.documentWidth<=geometry.width+1&&geometry.bodyWidth<=geometry.width+1,'Horizontal overflow: '+name+' '+JSON.stringify(geometry));
  const controls=[];
  for(const selector of selectors){
    const n=page.locator(selector);await n.waitFor({state:'visible'});await n.scrollIntoViewIfNeeded();const r=await n.boundingBox();assert(r&&r.width>0&&r.height>0,selector+' has no visible geometry');
    assert(r.x>=-1&&r.x+r.width<=geometry.width+1,'Control clipped horizontally: '+name+' '+selector+' '+JSON.stringify(r));
    const visible=await n.evaluate(node=>{const r=node.getBoundingClientRect(),s=getComputedStyle(node),x=(Math.max(0,r.left)+Math.min(innerWidth,r.right))/2,y=(Math.max(0,r.top)+Math.min(innerHeight,r.bottom))/2,h=document.elementFromPoint(x,y);return{visibility:s.visibility,intersects:r.right>0&&r.bottom>0&&r.left<innerWidth&&r.top<innerHeight,hit:!!h&&(h===node||node.contains(h)),hitId:h?.id||h?.tagName};});
    assert(visible.visibility==='visible'&&visible.intersects&&visible.hit,'Control obscured or clipped: '+name+' '+selector+' '+JSON.stringify(visible));
    controls.push({selector,bounds:r});
  }
  const file=path.join(path.dirname(output),'usability-'+name+'.png');await page.screenshot({path:file});report.screenshots.push(file);report.layouts.push({name,...geometry,controls});
}
main().then(()=>{report.status='passed';}).catch(error=>{report.status='failed';report.error=error.stack||String(error);process.exitCode=1;}).finally(async()=>{
  const cleanup=async(name,action)=>{try{await action();}catch(error){(report.cleanupErrors??=[]).push({name,error:String(error)});report.status='failed';process.exitCode=1;}};
  if(native&&investigation)await cleanup('delete-test-snapshot',async()=>{await page.waitForFunction(()=>!window.QuixiInvestigations?.busy);await native('investigation/delete',{project:project.id,id:investigation.id});});
  if(native&&opened)await cleanup('close-test-binary',async()=>{const result=await native('rea/tool',{project:project.id,tool:'close_binary',arguments:{}});assert.notEqual(result.failed,true,JSON.stringify(result.response));});
  if(page&&preferences)await cleanup('restore-ui-preferences',async()=>{await page.evaluate(p=>{for(const[k,v]of Object.entries(p))if(v===null)localStorage.removeItem(k);else localStorage.setItem(k,v);},preferences);await page.setViewportSize({width:1440,height:920});await page.reload();});
  if(browser)await browser.close().catch(error=>{report.cleanupError=String(error);report.status='failed';process.exitCode=1;});
  report.finishedAt=new Date().toISOString();report.durationMs=Math.round(performance.now()-started);
  if(output)fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({...report,reportPath:output}));
});
