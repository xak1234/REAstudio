// Pure input/view contract checks. Native provider behavior is checked by smoke-windows.cjs.
const assert = require('node:assert/strict');
const {defaults, issues, nativeView, pageArguments, procedure, sameTarget, visible, cTokens, address, fillArgs, functionRecord,
  filterHistory, historyFacets, sequencer, oraclePlan, formatSize, rawText, rowMatches} = require('../resources/playground/analysis.js');
const search = {name:'search_strings',inputSchema:{type:'object',additionalProperties:false,required:['pattern'],properties:{pattern:{type:'string',minLength:1},mode:{type:'string',enum:['literal','regex']},detail:{type:'string',enum:['complete','summary']}}}};
const decompile = {name:'procedure_pseudo_code',inputSchema:{type:'object',required:['procedure'],properties:{procedure:{type:'string'}}}};
assert.deepEqual(defaults(search,'',''),{pattern:'',detail:'summary'});
for(const pattern of ['', '   ', null, 12]) assert(issues(search,{pattern}).length);
assert(issues(search,{}).length);
assert(issues(search,[]).length);
assert(issues(search,{pattern:'test',mode:'unknown'}).length);
assert(issues(search,{pattern:'test',unexpected:true}).length);
assert.deepEqual(issues(search,{pattern:'LoadLibrary',detail:'summary'}),[]);
assert.deepEqual(issues(search,{pattern:'^Load.*',mode:'regex'}),[]);
assert(issues(decompile,{procedure:''}).length);
assert.deepEqual(issues(decompile,{procedure:'0x401000'}),[]);
assert.deepEqual(defaults({name:'open_binary',inputSchema:{required:['path'],properties:{path:{type:'string'},provider_id:{type:'string'}}}},'C:\\Original\\app.exe','ghidra'),{path:'C:\\Original\\app.exe',provider_id:'ghidra'});
const view={kind:'native-inventory',parent_operation:'list_procedures',parent_evidence_id:'retained-id'};
assert.equal(nativeView({normalized_result:view}),view);
assert.equal(nativeView({normalized_result:{...view,parent_operation:'unrelated'}}),null);
assert.deepEqual(pageArguments(view,50),{source:{kind:'retained-evidence',evidence_id:'retained-id'},view:{kind:'native-inventory',offset:50,limit:50}});
assert.throws(()=>pageArguments(view,-1),/Invalid evidence page/);
assert.throws(()=>pageArguments(view,0,101),/Invalid evidence page/);
assert.equal(procedure({record:{address:'0x401000',value:'main',procedure:{external:false}}}),'0x401000');
assert.equal(procedure({record:{address:'EXTERNAL:0x1',procedure:{external:true}}}),null);
assert.equal(procedure({record:{value:'LoadLibraryA',symbol:{external:true}}}),null);
assert.equal(sameTarget('C:\\Original\\app.exe','\\\\?\\c:\\original\\APP.EXE'),true);
assert.equal(sameTarget('C:\\Original\\one.exe','C:\\Original\\two.exe'),false);
assert.equal(sameTarget('',''),false);
// Hidden characters render as visible escapes; code keeps its tabs and line breaks.
assert.equal(visible('admin\u202Etxt.exe'), 'admin\\u202Etxt.exe');
assert.equal(visible('a\u200Bb\u200Dc\uFEFF'), 'a\\u200Bb\\u200Dc\\uFEFF');
assert.equal(visible('x\u0000y\u001B\u007F\u0085'), 'x\\u0000y\\u001B\\u007F\\u0085');
assert.equal(visible('line\nnext\ttab'), 'line\\nnext\\ttab');
assert.equal(visible('line\nnext\ttab', true), 'line\nnext\ttab');
assert.equal(visible('if (x) {\u2066 /* } */\u2069', true), 'if (x) {\\u2066 /* } */\\u2069');
assert.equal(visible('tag\u{E0041}'), 'tag\\u{E0041}');
assert.equal(visible('naïve 名前'), 'naïve 名前');
assert.equal(visible(null), '');
// The C tokeniser returns plain strings that reassemble the input; markup stays text.
const source = '#include <x.h>\n/* multi\nline */ int FUN_00401000(char *p) {\n  // "<script>"\n  if (p == "<img src=x onerror=alert(1)>") return 0x10;\n  return sub_401000(\'\\\'\', 1.5e3);\n}';
const tokens = cTokens(source);
assert.equal(tokens.map(t => t.text).join(''), source);
for (const t of tokens) { assert.equal(typeof t.text, 'string'); assert.deepEqual(Object.keys(t).sort(), ['text', 'type']); }
const kind = text => tokens.find(t => t.text === text)?.type;
assert.equal(kind('#include <x.h>'), 'preproc');
assert.equal(kind('/* multi\nline */'), 'comment');
assert.equal(kind('// "<script>"'), 'comment');
assert.equal(kind('"<img src=x onerror=alert(1)>"'), 'string');
assert.equal(kind('int'), 'type'); assert.equal(kind('char'), 'type');
assert.equal(kind('if'), 'keyword'); assert.equal(kind('return'), 'keyword');
assert.equal(kind('0x10'), 'number'); assert.equal(kind('1.5e3'), 'number');
assert.equal(kind('FUN_00401000'), 'ident'); assert.equal(kind('sub_401000'), 'ident');
assert.equal(cTokens('/* unterminated\nstill comment').length, 1);
assert.deepEqual(cTokens(''), []);
assert.equal(cTokens('a'.repeat(5000) + ' b').length, 3);
// Addresses normalise for matching; names never look like addresses.
assert.equal(address('0x00401000'), '0x401000');
assert.equal(address('00401000'), null);
assert.equal(address('00401000', true), '0x401000');
assert.equal(address('ram:0040A0', true), '0x40a0');
assert.equal(address('main', true), null);
// Live schema field names: REA uses procedure/address, IDA-style tools use addr/addrs and nested batches.
const ref = {$defs:{s0:{type:'string'},s1:{$ref:'#/$defs/s0'}},type:'object',properties:{procedure:{$ref:'#/$defs/s1'},document:{$ref:'#/$defs/s0'}},required:['procedure']};
assert.deepEqual(fillArgs(ref, {address:'0x401000'}), {procedure:'0x401000'});
assert.deepEqual(fillArgs({properties:{address:{type:'string'},document:{type:'string'}}}, {address:'0x401000'}), {address:'0x401000'});
assert.deepEqual(fillArgs({properties:{address:{type:'string'},name:{type:'string'}}}, {address:'0x1',name:'parse_header'}), {address:'0x1',name:'parse_header'});
assert.deepEqual(fillArgs({properties:{addr:{type:'string'}}}, {address:'0x1'}), {addr:'0x1'});
assert.deepEqual(fillArgs({properties:{addrs:{type:'array',items:{type:'string'}}}}, {address:'0x1'}), {addrs:['0x1']});
assert.deepEqual(fillArgs({properties:{items:{type:'array',items:{type:'object',properties:{addr:{type:'string'},comment:{type:'string'}}}}}}, {address:'0x1',comment:'checked'}), {items:[{addr:'0x1',comment:'checked'}]});
assert.deepEqual(fillArgs({properties:{batch:{type:'object',properties:{data:{type:'array',items:{type:'object',properties:{addr:{type:'string'},name:{type:'string'}}}},func:{type:'array',items:{type:'object',properties:{addr:{type:'string'},name:{type:'string'}}}}}}}}, {address:'0x1',name:'f'}), {batch:{func:[{addr:'0x1',name:'f'}]}});
assert.deepEqual(fillArgs({}, {address:'0x1'}), {});
// Decompile provenance accepts only successful original function evidence.
assert.equal(functionRecord({tool:'procedure_pseudo_code',failed:false}), true);
assert.equal(functionRecord({tool:'decompile',provider:'ida',failed:false}), true);
assert.equal(functionRecord({tool:'procedure_pseudo_code',failed:true}), false);
assert.equal(functionRecord({tool:'decompile_assist',kind:'model-suggestion'}), false);
assert.equal(functionRecord({tool:'list_procedures'}), false);
assert.equal(functionRecord({tool:'procedure_pseudo_code',transient:true}), false);
assert.equal(functionRecord(null), false);
// IDA bridge records (provider "ida-bridge") feed the Decompile helper like REA records; the input type must match the helper model.
const G0 = require('../resources/playground/analysis.js');
assert.equal(functionRecord({tool:'decompile',provider:'ida-bridge',kind:'ida'}), true);
assert.equal(functionRecord({tool:'disasm',provider:'ida-bridge',kind:'ida'}), true);
assert.equal(G0.helperInputKind({tool:'decompile',provider:'ida-bridge'}), 'pseudocode');
assert.equal(G0.helperInputKind({tool:'disasm',provider:'ida-bridge'}), 'assembly');
assert.equal(G0.helperInputKind({tool:'procedure_assembly'}), 'assembly');
assert.equal(G0.helperInputKind({tool:'analyze_function'}), '');
assert.equal(G0.helperInputIssue({tool:'decompile',provider:'ida-bridge'}, 'llm4-ref'), '');
assert.equal(G0.helperInputIssue({tool:'disasm',provider:'ida-bridge'}, 'llm4-end'), '');
assert.match(G0.helperInputIssue({tool:'disasm',provider:'ida-bridge'}, 'llm4-ref'), /holds assembly.*takes pseudocode/);
assert.match(G0.helperInputIssue({tool:'decompile_assist',kind:'model-suggestion'}, 'llm4-ref'), /Select a successful original function record/);
// Helper input type is detected from the model id; explicit words win, then upstream release naming, then Ref.
assert.equal(G0.helperProfile('LLM4Binary/llm4decompile-9b-ref').profile, 'llm4-ref');
assert.equal(G0.helperProfile('llm4decompile-6.7b-end').profile, 'llm4-end');
assert.equal(G0.helperProfile('llm4decompile_end_v2').profile, 'llm4-end');
assert.equal(G0.helperProfile('LLM4Binary/llm4decompile-6.7b-v1.5').profile, 'llm4-end');
assert.equal(G0.helperProfile('LLM4Binary/llm4decompile-22b-v2').profile, 'llm4-ref');
assert.equal(G0.helperProfile('my-local-model').profile, 'llm4-ref');
assert.equal(G0.helperProfile('refined-backend').profile, 'llm4-ref', 'substrings inside words do not count');
assert.equal(G0.helperProfile('refined-backend').reason, 'default');
// Helper status line is derived from decompile/status and configured connections only.
const conns = [{id:'local', name:'Local llama.cpp', configured:true}, {id:'gone', name:'Gone', configured:false}];
assert.equal(G0.helperStatus(null).state, 'unknown');
assert.equal(G0.helperStatus({settings:{enabled:false, model:''}}, conns).text, 'Off · Set up');
assert.equal(G0.helperStatus({settings:{enabled:false, provider:'local', model:'llm4-ref'}}, conns).text, 'Off · llm4-ref via Local llama.cpp saved');
assert.equal(G0.helperStatus({settings:{enabled:true, provider:'local', model:''}}, conns).text, 'Needs a model');
assert.equal(G0.helperStatus({settings:{enabled:true, provider:'gone', model:'m'}}, conns).text, 'Needs a connection');
assert.equal(G0.helperStatus({settings:{enabled:true, provider:'local', model:'m'}}, conns).text, 'On · m via Local llama.cpp');
assert.equal(G0.helperStatus({settings:{enabled:true, provider:'local', model:'m'}, connected:true}, conns).state, 'ready');
// Connection rows report saved state and the last real test only.
assert.equal(G0.connectionStatus({lastTestedOk:null}).text, 'Not tested');
assert.equal(G0.connectionStatus({lastTestedOk:true, lastLatencyMs:42}).text, 'Last test passed · 42 ms');
assert.equal(G0.connectionStatus({lastTestedOk:false}).text, 'Last test failed');
assert.equal(G0.connectionStatus({baseUrl:'http://127.0.0.1:8080/v1', credentialSource:'environment', environmentVariable:'X_KEY', models:[{id:'a'}]}).detail, 'http://127.0.0.1:8080/v1 · key from X_KEY · 1 model');
// History: newest first, filtered by target identity and tool.
const records = [
  {id:'a',target:'C:\\One\\app.exe',tool:'list_procedures',created:'2026-01-01T00:00:00Z'},
  {id:'b',target:'\\\\?\\c:\\one\\APP.EXE',tool:'procedure_pseudo_code',created:'2026-03-01T00:00:00Z'},
  {id:'c',target:'C:\\Two\\lib.dll',tool:'procedure_pseudo_code',created:'2026-02-01T00:00:00Z'}];
assert.deepEqual(filterHistory(records).map(r => r.id), ['b','c','a']);
assert.deepEqual(filterHistory(records, {target:'c:/one/app.exe'}).map(r => r.id), ['b','a']);
assert.deepEqual(filterHistory(records, {tool:'procedure_pseudo_code'}).map(r => r.id), ['b','c']);
assert.deepEqual(filterHistory(records, {target:'C:\\Two\\lib.dll',tool:'list_procedures'}), []);
assert.deepEqual(historyFacets(records), {targets:['C:\\One\\app.exe','C:\\Two\\lib.dll'],tools:['list_procedures','procedure_pseudo_code']});
assert.notEqual(filterHistory(records), records);
// Sequence guard: only the newest request may apply its response.
const seq = sequencer(), first = seq.next(), second = seq.next();
assert.equal(seq.current(first), false); assert.equal(seq.current(second), true);
// Oracle consent model shows exact commands, argv and expectations as escaped text.
const sha = 'a'.repeat(64);
const plan = oraclePlan({config:'d/oracle-cases.json',sha256:sha,approved:false,approvedSha256:null,cases:[
  {name:'help',command:'Write-Output ok\nRemove-Item -Recurse C:\\x',exitCode:0,stdout:'ok\n'},
  {name:'argv \u202Ecase',argv:['app.exe','two words','say "hi"'],stderr:''},
  {name:'',command:'   '}]});
assert.equal(plan.approved, false); assert.equal(plan.changed, false); assert.equal(plan.valid, true); assert.equal(plan.cases.length, 3);
assert.equal(plan.cases[0].command, 'Write-Output ok\nRemove-Item -Recurse C:\\x');
assert.deepEqual(plan.cases[0].expectations, ['exit code 0', 'stdout: ok\n']);
assert.equal(plan.cases[1].form, 'argv');
assert.equal(plan.cases[1].name, 'argv \\u202Ecase');
assert.equal(plan.cases[1].command, 'app.exe "two words" "say \\"hi\\""');
assert.deepEqual(plan.cases[1].expectations, ['stderr: ']);
assert.equal(plan.cases[2].name, 'Case 3'); assert.equal(plan.cases[2].missing, true);
assert.equal(oraclePlan({sha256:sha,approved:true,approvedSha256:sha,cases:[]}).approved, true);
assert.equal(oraclePlan({sha256:sha,approved:true,approvedSha256:sha,cases:[]}).empty, true);
const changed = oraclePlan({sha256:sha,approved:true,approvedSha256:'b'.repeat(64),cases:[]});
assert.equal(changed.approved, false); assert.equal(changed.changed, true);
assert.equal(oraclePlan({sha256:'not-a-hash',approved:true,cases:[]}).approved, false);
assert.deepEqual(oraclePlan(null).cases, []);
// Match reconstruction::describe's actual nested payload; legacy flat previews remain covered above.
const nestedPreview = oraclePlan({config:'d/oracle-cases.json',sha256:sha,cases:[{
  id:'outputs',name:'outputs',requirement:'REQ-OUTPUTS',expectationSource:'Source-known acceptance case',
  argv:['build/app.exe','write'],stdin:'input\n',timeoutSeconds:45,
  expected:{exitCode:0,stdout:'done\n',stderr:'',files:[
    {path:'output.txt',exists:true,text:'line one\nline two\n'},
    {path:'digest.bin',exists:true,sha256:'c'.repeat(64)},
    {path:'value.json',exists:true,json:null},
    {path:'empty.txt',exists:true,text:''},
    {path:'removed.tmp',exists:false}
  ]}
}]});
assert.equal(nestedPreview.cases[0].command,'build/app.exe write');
assert.deepEqual(nestedPreview.cases[0].expectations,[
  'exit code 0','stdout: done\n','stderr: ','timeout: 45 seconds',
  'file output.txt: must exist','  exact text: line one\nline two\n',
  'file digest.bin: must exist','  SHA-256: '+'c'.repeat(64),
  'file value.json: must exist','  JSON value: null',
  'file empty.txt: must exist','  exact text: ',
  'file removed.tmp: must be absent'
],'Approval must disclose every nested backend expectation, including empty text and JSON null');
const unspecifiedPreview=oraclePlan({sha256:sha,cases:[{name:'unset',command:'app.exe',timeoutSeconds:5,
  expected:{exitCode:null,stdout:null,stderr:null,files:[]}}]});
assert.deepEqual(unspecifiedPreview.cases[0].expectations,['timeout: 5 seconds'],'Unspecified backend expectations are not assertions');
// Large results: compact above the limit, capped for display.
assert.equal(formatSize(512), '512 B'); assert.equal(formatSize(2048), '2.0 KB'); assert.equal(formatSize(3 * 1048576), '3.0 MB');
assert.deepEqual(rawText('{"a":1}'), {text:'{\n  "a": 1\n}', pretty:true, truncated:false, size:7});
const big = JSON.stringify({rows:'x'.repeat(200)});
assert.equal(rawText(big, 100).pretty, false); assert.equal(rawText(big, 100).text, big);
assert.equal(rawText(big, 100, 50).text.length, 50); assert.equal(rawText(big, 100, 50).truncated, true);
// Client-side page filter.
assert.equal(rowMatches({record:{address:'0x401000',value:'ParseHeader'}}, 'parse'), true);
assert.equal(rowMatches({record:{address:'0x401000',value:'ParseHeader'}}, '4010'), true);
assert.equal(rowMatches({record:{address:'0x401000',value:'ParseHeader'}}, 'zzz'), false);
assert.equal(rowMatches({record:{}}, ''), true);
// ---- Guided workflow: data-driven stages and next steps from real-state snapshots ----
const G = require('../resources/playground/analysis.js');
const exe = 'C:\\Fake\\app.exe';
const base = {project:true, model:true, rea:{connected:true, catalog:true, tools:[]}, target:{path:exe, kind:'native'}, sources:['rea','ghidra']};
const ids = s => G.nextSteps(s).map(x => x.id);
const stage = (s, id) => G.reStages(s).find(x => x.id === id);
// Target kinds come from extensions, folders and result hints.
assert.equal(G.targetKind('C:\\a\\app.exe'), 'native'); assert.equal(G.targetKind('C:\\a\\lib.DLL'), 'native');
assert.equal(G.targetKind('C:\\a\\app.exe', false, {managed:true}), 'dotnet');
assert.equal(G.targetKind('C:\\a\\app.asar'), 'javascript'); assert.equal(G.targetKind('C:\\a\\electron-app', true), 'javascript');
assert.equal(G.targetKind('C:\\a\\x.apk'), 'apk'); assert.equal(G.targetKind('C:\\a\\notes.txt'), 'other'); assert.equal(G.targetKind(''), '');
assert.deepEqual(G.kindHint('inspect_managed_artifact', false, '{"result":{"is_managed":true}}'), {managed:true});
assert.deepEqual(G.kindHint('inspect_managed_artifact', true, '{"is_managed":true}'), {});
assert.deepEqual(G.kindHint('open_binary', false, '{"format":"pe"}'), {});
// Evidence comes only from successful records for the same target.
const ev = G.evidenceSummary([{tool:'list_procedures',target:'\\\\?\\c:\\fake\\APP.EXE'},{tool:'procedure_pseudo_code',target:exe,failed:true},{tool:'search_strings',target:'C:\\Other.exe'}], exe);
assert.equal(ev.functions, true); assert.equal(ev.decompiled, false); assert.equal(ev.strings, false);
// Connect, then target.
assert.deepEqual(ids({}).slice(0, 2), ['connect', 'select-target']);
assert.equal(stage({}, 'connect').status, 'current'); assert.equal(stage({}, 'target').status, 'todo');
assert.equal(ids({...base, target:{path:''}})[0], 'select-target');
// Native: open, list functions, decompile (+ strings, imports), then annotate / follow / use.
assert.equal(ids(base)[0], 'open-target');
assert.match(G.nextSteps(base)[0].why, /Ghidra in the background/); assert.equal(G.nextSteps(base)[0].tool, 'open_binary');
const opened = {...base, opened:true};
assert.deepEqual(ids(opened), ['list-functions']);
assert.equal(stage(opened, 'open').status, 'done');
assert.equal(stage(opened, 'explore').status, 'current', 'open alone is not exploration');
const listed = {...opened, evidence:{functions:true}};
assert.deepEqual(ids(listed), ['decompile-function', 'search-strings', 'list-imports']);
assert.equal(stage(listed, 'explore').status, 'current', 'a native function list alone is not recovered code');
assert.equal(stage(listed, 'explore').detail, 'functions');
assert.equal(stage({...base, target:{path:'C:\\a\\app.asar', kind:'javascript'}, evidence:{javascript:true}}, 'explore').status, 'done');
const decompiled = {...opened, evidence:{functions:true, decompiled:true}};
assert.deepEqual(ids(decompiled), ['annotate', 'follow-references', 'use-in-task']);
assert.match(G.nextSteps(decompiled)[0].why, /may refuse on Windows/);
const withIda = {...decompiled, ida:{installed:true, enabled:true, connected:true, session:true, allowAnnotations:true}};
assert.match(G.nextSteps(withIda)[0].why, /written to the IDB/);
assert.deepEqual(ids({...decompiled, evidence:{...decompiled.evidence, annotated:true}}).slice(0, 1), ['follow-references']);
// Specialist: enabled without a model is a config step; configured adds an assistant suggestion.
assert.equal(ids({...decompiled, specialist:{enabled:true, model:''}})[0], 'specialist-models');
assert.ok(G.nextSteps({...decompiled, evidence:{...decompiled.evidence, annotated:true}, specialist:{enabled:true, model:'llm4'}}).some(x => x.id === 'specialist'));
assert.deepEqual([G.nextSteps({...decompiled, specialist:{enabled:true, model:''}})[0].target, G.nextSteps({...decompiled, specialist:{enabled:true, model:''}})[0].action], ['helper-setup', 'helper']);
assert.equal(ids({...decompiled, specialist:{enabled:true, model:'llm4', connection:false}})[0], 'specialist-connection');
assert.ok(!G.nextSteps({...decompiled, evidence:{...decompiled.evidence, annotated:true}, specialist:{enabled:true, model:'llm4', connection:false}}, 10).some(x => x.id === 'specialist'));
assert.ok(!G.nextSteps({...decompiled, specialist:{enabled:false, model:''}}, 10).some(x => /^specialist/.test(x.id)));
assert.ok(G.nextSteps({...decompiled}, 10).every(x => x.target !== 'decompile-driver'), 'the driving-model picker is gone');
// Catalog filtering: tools the live catalog lacks are not suggested.
assert.deepEqual(ids({...listed, rea:{connected:true, catalog:true, tools:['procedure_pseudo_code','search_strings']}}), ['decompile-function', 'search-strings']);
// Other kinds.
assert.equal(ids({...base, target:{path:'C:\\a\\app.exe', kind:'dotnet'}})[0], 'dotnet-metadata');
assert.equal(ids({...base, target:{path:'C:\\a\\app.exe', kind:'dotnet'}, evidence:{managed:true}})[0], 'managed-members');
assert.equal(ids({...base, target:{path:'C:\\a\\app.asar', kind:'javascript'}})[0], 'javascript');
assert.equal(ids({...base, target:{path:'C:\\a\\app.asar', kind:'javascript'}, evidence:{javascript:true}})[0], 'trace-feature');
assert.equal(ids({...base, target:{path:'C:\\a\\x.apk', kind:'apk'}})[0], 'configure-jadx');
assert.equal(stage({...base, target:{path:'C:\\a\\x.apk', kind:'apk'}}, 'source').status, 'blocked');
assert.equal(ids({...base, target:{path:'C:\\a\\x.apk', kind:'apk'}, sources:['jadx-mcp']})[0], 'android');
assert.equal(ids({...base, target:{path:'C:\\a\\notes.txt', kind:'other'}})[0], 'inspect-artifact');
// IDA selected but unconfigured: prepare the bridge setup, then register; a headless registration clears it.
const idaSource = {...base, source:{id:'ida'}, provider:'ida'};
assert.deepEqual([G.nextSteps(idaSource)[0].id, G.nextSteps(idaSource)[0].kind, G.nextSteps(idaSource)[0].target], ['install-ida', 'config', 'ida-setup']);
assert.equal(stage(idaSource, 'source').status, 'blocked');
const idaInstalled = {...idaSource, ida:{installed:true}};
assert.equal(G.nextSteps(idaInstalled)[0].target, 'ida-register-rea'); assert.match(G.nextSteps(idaInstalled)[0].why, /reconnect REA/);
assert.equal(ids({...idaSource, ida:{installed:true, reaUsesHeadless:true}})[0], 'open-target');
assert.match(G.nextSteps({...idaSource, ida:{installed:true, reaUsesHeadless:true}})[0].why, /Starts IDA/);
assert.equal(ids({...base, source:{id:'ida-headless'}, ida:{installed:true}})[0], 'enable-ida');
assert.equal(ids({...base, source:{id:'ida-headless'}, ida:{installed:true, enabled:true, connected:true}})[0], 'open-ida');
// x64dbg.
assert.equal(ids({...base, source:{id:'x64dbg'}})[0], 'enable-debugger');
assert.equal(ids({...base, source:{id:'x64dbg'}, debugger:{connected:true}})[0], 'debugger-session');
// A failed record surfaces the provider's own error and remediation, escaped, before anything else.
const failedRecord = {id:'rec-9', tool:'procedure_pseudo_code', failed:true, response:{content:[{type:'text', text:'boom'}]}};
const info = G.failureInfo(failedRecord, {error:{message:'Function not found \u202E'}, remediation:'Run list_procedures first', details:{next_steps:['Open the target','Open the target'], hint:{tool:'open_binary'}}});
assert.equal(info.error, 'Function not found \\u202E');
assert.deepEqual(info.remediation, ['Run list_procedures first', 'Open the target', 'open_binary']);
assert.equal(G.failureInfo({failed:false}, {}), null);
assert.equal(G.failureInfo(failedRecord, failedRecord.response).error, 'boom');
const failing = G.nextSteps({...decompiled, last:info});
assert.equal(failing[0].id, 'fix-rec-9'); assert.match(failing[0].why, /Function not found \\u202E/); assert.match(failing[0].why, /Provider guidance: Run list_procedures first/);
const peFail = G.failureInfo({id:'r1', tool:'inspect_pe_resources', failed:true}, {error:{message:'Resource range is not entirely file-backed in one section.'}});
assert.deepEqual(ids({...base, last:peFail}).slice(0, 2), ['fix-r1', 'fix-pe-resources']);
const pathFail = G.failureInfo({id:'r2', tool:'open_binary', failed:true}, {error:{message:'Ghidra project path failed containment check'}});
assert.deepEqual(ids({...base, last:pathFail}).slice(0, 2), ['fix-r2', 'fix-local-path']);
// Rebuild and verify stages.
const evidence = {...decompiled, evidence:{functions:true, decompiled:true, annotated:true}};
const rebuildId = s => G.nextSteps(s, 10).map(x => x.id).filter(id => ['open-project','providers','prepare-analysis','save-spec','oracle-cases','oracle-run','oracle-retry','next-milestone'].includes(id));
assert.deepEqual(rebuildId({...evidence, project:false}), ['open-project']);
assert.deepEqual(rebuildId(evidence), ['prepare-analysis']);
assert.deepEqual(rebuildId({...evidence, model:false}), ['providers', 'prepare-analysis']);
assert.equal(G.nextSteps({...evidence, model:false}, 10).find(x => x.id === 'providers').action, 'providers');
const agentStep = G.nextSteps({...evidence, model:false, connections:2}, 10).find(x => x.id === 'agent-model');
assert.deepEqual([agentStep.target, agentStep.action], ['model', undefined], 'with connections, the step points at the Agent model picker');
assert.ok(!G.nextSteps({...evidence, model:false, connections:2}, 10).some(x => x.id === 'providers'));
assert.deepEqual(rebuildId({...evidence, reconstruction:{brief:true}}), ['save-spec']);
assert.deepEqual(rebuildId({...evidence, reconstruction:{brief:true, dossier:'d1', oracleCases:0}}), ['oracle-cases']);
assert.equal(G.nextSteps({...evidence, reconstruction:{brief:true, dossier:'d1', oracleCases:0}}, 10).find(x => x.id === 'oracle-cases').action, 'openOracleCases');
assert.deepEqual(rebuildId({...evidence, reconstruction:{brief:true, dossier:'d1', oracleCases:2}}), ['oracle-run']);
assert.deepEqual(rebuildId({...evidence, reconstruction:{dossier:'d1', oracleCases:2, oracleStatus:'failed'}}), ['oracle-retry']);
assert.deepEqual(rebuildId({...evidence, reconstruction:{dossier:'d1', oracleCases:2, oracleStatus:'passed'}}), ['next-milestone']);
assert.equal(stage({...evidence, reconstruction:{dossier:'d1', oracleStatus:'passed'}}, 'verify').status, 'done');
assert.equal(stage({...evidence, reconstruction:{dossier:'d1', oracleCases:0}}, 'verify').detail, 'Oracle suite is empty');
assert.deepEqual(rebuildId({...opened, evidence:{functions:true}}), [], 'function lists alone are not enough to rebuild');
// Dismissals filter by step id; ordering is stable and capped.
assert.deepEqual(ids({...listed, dismissed:['decompile-function']}), ['search-strings', 'list-imports']);
assert.deepEqual(ids(listed), ids(JSON.parse(JSON.stringify(listed))));
assert.ok(G.nextSteps(evidence).length <= 3);
assert.deepEqual(G.reStages(base).map(x => x.id), ['connect','target','source','open','explore','annotate','rebuild','verify']);
assert.equal(G.reStages(base).filter(x => x.status === 'current').length, 1);
// Quick-action preflight.
assert.equal(G.preflight('list_procedures', {}).step.id, 'connect');
assert.equal(G.preflight('open_binary', {...base, target:{path:''}}).step.id, 'select-target');
assert.equal(G.preflight('list_procedures', base).step.id, 'open-target');
assert.equal(G.preflight('list_procedures', opened), null);
assert.equal(G.preflight('procedure_pseudo_code', opened, {procedure:''}).step.id, 'list-functions');
assert.equal(G.preflight('procedure_pseudo_code', listed, {procedure:''}).step.id, 'decompile-function');
assert.equal(G.preflight('procedure_pseudo_code', listed, {procedure:'0x401000'}), null);
assert.equal(G.preflight('inspect_android_package', base).step.id, 'configure-jadx');
assert.equal(G.preflight('', base), null);
assert.equal(G.idaPreflight('read', {}).step.id, 'install-ida');
assert.equal(G.idaPreflight('read', {ida:{installed:true}}).step.id, 'enable-ida');
assert.equal(G.idaPreflight('read', {ida:{installed:true, enabled:true, connected:true}}).step.id, 'open-ida');
assert.equal(G.idaPreflight('annotate', {ida:{installed:true, enabled:true, connected:true, session:true}}).step.id, 'ida-annotations');
assert.equal(G.idaPreflight('read', {ida:{installed:true, enabled:true, connected:true, session:true}}), null);
assert.equal(G.idaPreflight('read', {ida:{unsupported:true}}).step, null);
// ---- Coding workspace helpers ----
const W = require('../resources/playground/analysis.js');
assert.equal(W.normalizeEol('a\r\nb\rc\n'), 'a\nb\nc\n');
assert.equal(W.fileFormat({lineEnding:'crlf', bom:true}), 'CRLF · UTF-8 (BOM)');
assert.equal(W.fileFormat({lineEnding:'mixed'}), 'Mixed line endings — saving will normalise to LF · UTF-8', 'mixed files are saved as LF, and the status says so');
assert.equal(W.fileFormat(null), 'LF · UTF-8', 'older builds without lineEnding are LF');
for (const p of ['Makefile', 'src\\GNUmakefile', 'rules.mk', 'cmd/main.go', 'data.tsv']) assert.equal(W.indentUnit(p, ''), '\t', p);
assert.equal(W.indentUnit('a.c', '    x\n    y'), '    ');
assert.equal(W.indentUnit('a.c', '\tx\n\ty\n  z'), '\t', 'existing tab indentation is kept');
assert.deepEqual(W.lineDiff('a\nb\nc', 'a\nB\nc'), [{cls:'hunk', text:'@@ 1 unchanged line @@'}, {cls:'removed', text:'-b'}, {cls:'added', text:'+B'}, {cls:'hunk', text:'@@ 1 unchanged line @@'}]);
assert.deepEqual(W.lineDiff('x\r\ny', 'x\ny'), [{cls:'hunk', text:'@@ 2 unchanged lines @@'}], 'line endings alone are not a change');
assert.equal(W.lineDiff('a\n'.repeat(3000) + 'x', 'b\n'.repeat(3000) + 'y'), null);
const bigDiff = Array.from({length: 12001}, (_, i) => i % 2 ? `+${i}` : `-${i}`).join('\n');
const page1 = W.diffLines(bigDiff);
assert.equal(page1.lines.length, 5000); assert.equal(page1.next, 5000); assert.equal(page1.total, 12001);
assert.equal(W.diffLines(bigDiff, 10000).next, null); assert.equal(W.diffLines(bigDiff, 10000).lines.length, 2001);
assert.deepEqual(W.diffLines('@@ -1 +1 @@\n-a\n+b\n c').lines.map(l => l.cls), ['hunk', 'removed', 'added', '']);
assert.deepEqual(W.appendChunks([{stream:'stdout', text:'a'}], [{stream:'stdout', text:'b'}, {stream:'stderr', text:'E'}, {stream:'stderr', text:''}, {stream:'weird', text:'c'}]),
  [{stream:'stdout', text:'ab'}, {stream:'stderr', text:'E'}, {stream:'stdout', text:'c'}]);
assert.deepEqual(W.rememberCommand(['a', 'b'], 'b'), ['a', 'b']);
assert.equal(W.rememberCommand(Array.from({length: 200}, (_, i) => String(i)), 'new').length, 200);
assert.deepEqual(W.recallCommand(['a', 'b'], 2, -1, 'draft'), {index:1, value:'b'});
assert.deepEqual(W.recallCommand(['a', 'b'], 0, -1, 'draft'), {index:0, value:'a'});
assert.deepEqual(W.recallCommand(['a', 'b'], 1, 1, 'draft'), {index:2, value:'draft'});
assert.equal(W.runMeta({provider:'custom', model:'m', mode:'code', created:1000, finished:126000, steps:4}), 'custom / m · code · 2m 05s · 4 steps');
assert.equal(W.runMeta({model:'m', mode:'ask', status:'running', created:0}, 3000), 'm · ask · 3s');
assert.equal(W.runMeta({model:'m', mode:'code', status:'completed', created:0, startedAt:1000, finishedAt:66000, steps:1}), 'm · code · 1m 05s · 1 step', 'engine startedAt/finishedAt (ms) drive the elapsed time');
assert.equal(W.runMeta({model:'m', mode:'ask', status:'running', created:0, startedAt:2000}, 5000), 'm · ask · 3s', 'a running task counts from startedAt');
assert.equal(W.runMeta({model:'m\u202E', mode:'ask', status:'completed', created:0}), 'm\\u202E · ask', 'no end time, no elapsed; hidden characters escaped');
assert.ok(W.runMatches({prompt:'Fix the parser', status:'completed'}, 'PARSER'));
assert.ok(!W.runMatches({prompt:'Fix the parser'}, 'lexer'));
assert.ok(W.activeRunStatuses.includes('awaiting_approval'));
assert.deepEqual(W.pendingCommand('rm -rf build\u202E'), {command:'rm -rf build\\u202E', detail:''});
assert.deepEqual(W.pendingCommand({command:'git push\n--force', cwd:'C:\\p', reason:'network'}), {command:'git push\n--force', detail:'Working directory: C:\\p\nWhy approval is needed: network'});
assert.equal(W.pendingCommand({argv:['del', 'x']}).command, 'del x');
assert.deepEqual(W.forceableSkips([{path:'a', reason:'Already reverted'}, {path:'b', reason:'The file changed after the task wrote it; use force to overwrite those changes'},
  {path:'c', reason:'This task did not change that file'}, {path:'d', reason:'The file was removed after the task wrote it; use force to restore it'}]).map(s => s.path), ['b', 'd'], 'force is only offered where it can help');
assert.deepEqual(W.forceableSkips(undefined), []);
assert.deepEqual(W.gitFileLabel({status:'M', additions:3, deletions:1, staged:true}), {letter:'M', counts:'+3 −1', staged:true});
assert.equal(W.gitFileLabel({status:'??'}).letter, 'U');
assert.equal(W.gitFileLabel({status:'deleted', deletions:4}).counts, '+0 −4');
assert.equal(W.gitFileLabel({status:'renamed'}).letter, 'R');
console.log('Analysis checks passed: required inputs, live-schema preflight, retained paging, function selection, target identity, hidden-character escaping, C tokens, schema field mapping, history filters, sequence guards, oracle consent, large-result display, the guided workflow rules, the Models/helper roles and the coding workspace helpers.');
