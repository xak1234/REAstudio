// Real HTTP/MCP client integration against an isolated running REA Studio profile.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const {chromium} = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
const sdk = process.env.REA_STUDIO_TEST_SDK;
assert(sdk, 'Set REA_STUDIO_TEST_SDK to the official @modelcontextprotocol/sdk package directory');
const {Client} = require(path.join(sdk,'dist/cjs/client/index.js'));
const {StreamableHTTPClientTransport} = require(path.join(sdk,'dist/cjs/client/streamableHttp.js'));
const listen = (server, port=0) => new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>resolve(server.address().port));});
const close = server => new Promise(resolve=>{server.close(resolve);server.closeAllConnections?.();});
async function mcpPort(){for(let i=0;i<20;i++){const probe=net.createServer();try{const port=await listen(probe,20000+Math.floor(Math.random()*40000));await close(probe);return port;}catch(e){if(e.code!=='EADDRINUSE')throw e;}}throw Error('No free MCP test port');}
(async()=>{
  const root=process.env.QUIXI_SMOKE_ROOT, profile=process.env.REA_STUDIO_TEST_DATA;
  const key=process.env.REA_STUDIO_TEST_EXPECTED_ENV_KEY;
  assert(root && profile && key,'Use an isolated fixture root/profile and a non-secret environment test value');
  const browser=await chromium.connectOverCDP('http://127.0.0.1:9322');
  const page=browser.contexts()[0].pages().find(p=>p.url().includes('app.localhost/playground'));assert(page);
  page.setDefaultTimeout(15000);page.setDefaultNavigationTimeout(15000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const native=(route,data={})=>page.evaluate(async({route,data})=>{const r=await fetch('/api/quixi/'+route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const v=await r.json();if(!r.ok)throw Error(v.error || String(r.status));return v;},{route,data});
  let client;let provider;let authorizedModels=0,authorizedCompletions=0;
  try{
    console.log('MCP check: loading app');await page.reload();await page.locator('#connection').filter({hasText:'Connected'}).waitFor();
    assert.equal((await native('mcp/status')).enabled,false);
    const port=await mcpPort();
    await page.locator('#mcp-settings').click();await page.locator('#mcp-port').fill(String(port));await page.locator('#mcp-toggle').click();
    await page.waitForFunction(()=>document.getElementById('mcp-status').textContent==='Enabled');
    await page.locator('#mcp-config').click();await page.waitForFunction(()=>document.getElementById('mcp-config-output').textContent.includes('mcpServers'));const config=JSON.parse(await page.locator('#mcp-config-output').textContent()).mcpServers['rea-studio'];
    assert.equal(new URL(config.url).port,String(port));
    const headers={...config.headers,'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'};
    const raw=(body,overrides={})=>fetch(config.url,{method:'POST',headers:{...headers,...overrides},body:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
    const ping={jsonrpc:'2.0',id:1,method:'ping'};
    assert.equal((await raw(ping,{Authorization:'Bearer incorrect'})).status,401);
    assert.equal((await raw(ping,{Origin:'https://untrusted.invalid'})).status,403);
    assert.equal((await raw(ping,{'MCP-Protocol-Version':'unsupported'})).status,400);
    assert.equal((await fetch(config.url,{method:'GET',headers})).status,405);
    client=new Client({name:'rea-studio-integration-check',version:'1.1.0'});
    await client.connect(new StreamableHTTPClientTransport(new URL(config.url),{requestInit:{headers:config.headers}}));
    assert.equal(client.getServerVersion().name,'rea-studio');assert.equal(client.getServerVersion().version,'1.1.0');
    const catalog=await client.listTools();assert.equal(catalog.tools.length,17);
    const call=async(name,args={})=>{const r=await client.callTool({name,arguments:args});assert.equal(r.isError,false,JSON.stringify(r));return r.structuredContent || JSON.parse(r.content[0].text);};
    console.log('MCP check: official client connected');const state=await call('studio_state');assert(!JSON.stringify(state).includes(config.headers.Authorization));assert(!JSON.stringify(state).includes(key));
    const project=await call('studio_open_project',{path:root});
    const filename='mcp-check-'+Date.now()+'.txt';
    await call('studio_write_file',{project:project.id,path:filename,content:'MCP wrote this file.\n',hash:''});
    const read=await call('studio_read_file',{project:project.id,path:filename});assert.equal(read.content,'MCP wrote this file.\n');assert(read.hash);
    const conflict=await client.callTool({name:'studio_write_file',arguments:{project:project.id,path:filename,content:'bad overwrite',hash:'stale'}});assert.equal(conflict.isError,true);
    assert.equal(fs.readFileSync(path.join(root,filename),'utf8'),'MCP wrote this file.\n');
    const escaped=await client.callTool({name:'studio_read_file',arguments:{project:project.id,path:'../outside.txt'}});assert.equal(escaped.isError,true);
    const command=await call('studio_command',{project:project.id,command:"[Console]::Write('mcp-command-ok')"});assert.equal(command.stdout,'mcp-command-ok');assert.equal(command.exitCode,0);
    const rea=await call('studio_rea_catalog',{tool:'search_strings'});assert.equal(rea.name,'search_strings');assert(rea.inputSchema.required.includes('pattern'));
    await page.locator('#mcp-close').click();await page.waitForFunction(()=>document.getElementById('mcp-config-output').textContent==='');
    await page.locator('#project').selectOption(project.id);await page.locator('.file-row[title="README.md"]').click();
    await page.locator('#editor').fill('Unsaved work survives an incoming MCP project.\n');
    const source='export function sum(a, b) { return a + b; }\n';
    const coding=await call('studio_import_code',{name:'Agent coding fixture',purpose:'coding',files:[{path:'src/main.js',content:source},{path:'README.md',content:'Received for coding assistance.\n'}]});
    const analysis=await call('studio_import_code',{name:'Agent analysis fixture',purpose:'analysis',files:[{path:'package.json',content:JSON.stringify({name:'rea-import-fixture',version:'1.0.0',type:'module'})},{path:'src/main.js',content:source}]});
    assert.equal(coding.executed,false);assert.equal(analysis.executed,false);
    assert.equal(fs.readFileSync(path.join(coding.project.path,'src/main.js'),'utf8'),source);
    const importedRead=await call('studio_read_file',{project:coding.project.id,path:'src/main.js'});assert.equal(importedRead.content,source);
    const badImport=await client.callTool({name:'studio_import_code',arguments:{name:'Bad path',files:[{path:'../escape.js',content:'bad'}]}});assert.equal(badImport.isError,true);
    await page.locator('#received-code-note').filter({hasText:'Agent analysis fixture'}).waitFor();
    assert.equal(await page.locator('#project').inputValue(),project.id);assert.equal(await page.locator('#editor').inputValue(),'Unsaved work survives an incoming MCP project.\n');
    page.once('dialog',d=>d.dismiss());await page.locator('#received-code-open').click();
    assert.equal(await page.locator('#project').inputValue(),project.id);assert.equal(await page.locator('#editor').inputValue(),'Unsaved work survives an incoming MCP project.\n');
    await page.locator('#save').click();await page.waitForFunction(()=>document.getElementById('dirty').hidden);
    await page.locator('#received-code-open').click();await page.waitForFunction(()=>document.getElementById('artifact-name').textContent.startsWith('received-code-'));
    assert.equal(await page.locator('#project').inputValue(),analysis.project.id);
    await call('studio_rea_select',{path:analysis.analysisTarget});
    const inspected=await call('studio_rea_call',{tool:'analyze_javascript_application',arguments:{input_path:analysis.analysisTarget,detail:'summary'}});assert.equal(inspected.failed,false);
    await page.locator('#received-code-note').filter({hasText:'Agent coding fixture'}).waitFor();await page.locator('#received-code-open').click();
    await page.waitForFunction(source=>document.getElementById('editor').value===source,source);
    assert.equal(await page.locator('#project').inputValue(),coding.project.id);
    await page.locator('#mcp-settings').click();
    console.log('MCP check: source import, unsaved work preservation, user handoff and real code analysis passed');
    console.log('MCP check: file, conflict, command and REA checks passed');
    // A bounded local HTTP fixture verifies that the actual app sends its ENV credential.
    provider=http.createServer((req,res)=>{
      if(req.headers.authorization!=='Bearer '+key){res.writeHead(401);res.end('{}');return;}
      if(req.url==='/v1/models'){authorizedModels++;res.setHeader('Content-Type','application/json');res.end(JSON.stringify({data:[{id:'env-fixture'}]}));return;}
      if(req.url==='/v1/chat/completions'){
        authorizedCompletions++;req.resume();req.on('end',()=>{res.setHeader('Content-Type','text/event-stream');res.end('data: '+JSON.stringify({choices:[{delta:{content:JSON.stringify({action:'done',summary:'Environment credential verified.'})}}]})+'\n\ndata: [DONE]\n\n');});return;
      }
      res.writeHead(404);res.end('{}');
    });
    const providerPort=await listen(provider);const providerBody={providerId:'custom',baseUrl:`http://127.0.0.1:${providerPort}/v1`,selectedModel:'env-fixture',apiKey:'',completeOnboarding:true};
    const tested=await native('providers/test',providerBody);assert.equal(tested.ok,true);assert(authorizedModels>0);
    const saved=await native('providers/save',providerBody);const custom=saved.providers.find(p=>p.id==='custom');assert.equal(custom.credentialSource,'environment');assert.equal(custom.environmentVariable,'CUSTOM_API_KEY');assert(!JSON.stringify(saved).includes(key));assert(!fs.readFileSync(path.join(profile,'providers.json'),'utf8').includes(key));
    const run=await call('studio_start_run',{project:coding.project.id,prompt:'Verify the imported source project with the local environment credential fixture.',model:'env-fixture',mode:'ask'});
    let result;for(let i=0;i<40;i++){result=await call('studio_run_status',{id:run.id});if(result.status!=='running')break;await new Promise(resolve=>setTimeout(resolve,100));}
    assert.equal(result.status,'completed');assert.equal(result.reply,'Environment credential verified.');assert(authorizedCompletions>0);
    console.log('MCP check: ENV connection and model task passed');await page.locator('#mcp-close').click();await page.waitForFunction(()=>document.getElementById('mcp-config-output').textContent==='');
    await page.locator('#providers').click();await page.locator('#provider-id').selectOption('custom');assert.match(await page.locator('#provider-env').textContent(),/CUSTOM_API_KEY/);await page.locator('#close-provider').click();
    await page.locator('#mcp-settings').click();assert.equal(await page.locator('.classic-settings').evaluate(e=>e.open),false);
    console.log('MCP check: disabling listener');await page.locator('#mcp-toggle').click();await page.waitForFunction(()=>document.getElementById('mcp-status').textContent==='Disabled');
    await assert.rejects(new Promise((resolve,reject)=>{const socket=net.connect(port,'127.0.0.1');socket.once('connect',()=>{socket.destroy();resolve();});socket.once('error',reject);socket.setTimeout(3000,()=>{socket.destroy();reject(Error('Listener close timed out'));});}),{code:'ECONNREFUSED'});
    console.log('MCP check: listener stopped');await client.close();client=null;
    console.log('MCP check: rotating token');await native('mcp/rotate');await native('mcp/enable',{port});assert.equal((await raw(ping)).status,401);await native('mcp/disable');
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({passed:true,tools:catalog.tools.length,authentication:true,originCheck:true,realFileWrite:true,writeConflict:true,pathContainment:true,command:true,codeImport:true,importAnalysis:true,importCodingTask:true,unsavedWorkPreserved:true,envConnectionTest:true,envModelTask:true,envNotPersisted:true,disableClosesListener:true,tokenRotation:true,classicAccessCollapsed:true,jsErrors:errors}));
  } finally {
    console.log('MCP check: cleanup');await native('mcp/rotate').catch(()=>{});if(client)await client.close().catch(()=>{});if(provider)await close(provider);await browser.close();
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
