/* QuixiDesk's native playground. All workspace and analysis results come from Rust APIs. */
'use strict';
const $ = id => document.getElementById(id);
const state = { projects: [], runs: [], providers: {}, project: localStorage.getItem('quixi.project') || '',
  run: '', file: null, dirty: false, files: [], git: {}, rea: {connected:false, tools:[], availability:new Map(), records:[], target:''}, busy:false };
const el = (tag, text, className) => { const n=document.createElement(tag); if(text!==undefined)n.textContent=text; if(className)n.className=className; return n; };
const replace = (id, children) => $(id).replaceChildren(...children);
const option = (value,label) => {const n=el('option',label);n.value=value;return n;};
function error(e) { $('error').textContent=e?.message || String(e); $('error').hidden=false; }
function clearError() { $('error').hidden=true; }
async function api(route, data, prefix='/api/quixi/playground/') {
  const response=await fetch(prefix+route,{method:data===undefined?'GET':'POST',headers:data===undefined?{}:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});
  const result=await response.json();
  if(!response.ok || result.error)throw new Error(result.error || `Request failed: ${response.status}`);
  return result;
}
const pg=(route,data={})=>api(route,{project:state.project,...data});
const providerApi=(route,data)=>api(route,data,'/api/quixi/providers');
function on(id,event,callback) { $(id).addEventListener(event,async e=>{try{await callback(e);}catch(err){error(err);}}); }
async function busy(button, task, label='Working…') {
  const old=button.textContent;button.disabled=true;button.textContent=label;clearError();
  try{return await task();}finally{button.textContent=old;button.disabled=false;}
}
function showView(view) {
  document.querySelector('.workbench').classList.toggle('analysis-active',view==='analysis');
  document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.view===view)));
  document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!==`view-${view}`);
  if(view==='changes' && state.project)loadDiff().catch(error);
  if(view==='analysis')loadAnalysisHistory().catch(error);
}
function showConsole(name) {
  document.querySelectorAll('[data-console]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.console===name)));
  ['activity','terminal'].forEach(n=>$(`console-${n}`).hidden=n!==name);
}
function selectedRun(){return state.runs.find(r=>r.id===state.run);}
function running(){return state.runs.find(r=>['running','stopping'].includes(r.status));}
function requireProject(){if(!state.project)throw new Error('Open a project folder first.');}
function guardDirty(){return !state.dirty || window.confirm('Discard the unsaved changes in this editor?');}
async function askText(title,label,value=''){
  const dialog=$('text-dialog');$('text-title').textContent=title;$('text-label').textContent=label;$('text-value').value=value;dialog.returnValue='';dialog.showModal();$('text-value').focus();
  return new Promise(resolve=>dialog.addEventListener('close',()=>resolve(dialog.returnValue==='ok'?$('text-value').value.trim():null),{once:true}));
}
async function refreshState(){
  const data=await api('state');Object.assign(state,{projects:data.projects,runs:data.runs,providers:data.providers});
  if(!state.projects.some(p=>p.id===state.project))state.project=state.projects[0]?.id || '';
  $('connection').classList.remove('offline');replace('connection',[el('i'),document.createTextNode('Connected')]);
  $('host').textContent=data.host;$('execution-host').textContent=`${data.host} · ${data.platform}`;
  $('terminal-note').textContent=`Commands run locally in the selected project (${data.platform==='windows'?'PowerShell':'native shell'}).`;
  renderProjects();renderModels();renderRuns();updateControls();renderReconstruction();
  return data;
}
function renderProjects(){
  replace('project',[option('','Select a project'),...state.projects.map(p=>option(p.id,p.name))]);$('project').value=state.project;
  const p=state.projects.find(p=>p.id===state.project);$('project-name').textContent=p?.name || 'Your coding workspace';$('project-path').textContent=p?.path?.replace(/^\\\\\?\\/, '') || 'Open a local project to get started';
  $('project-path').title=p?.path || '';
}
function renderModels(){
  const current=$('model').value || localStorage.getItem('quixi.model') || state.providers.activeModel;
  const models=[];
  for(const p of state.providers.providers || [])if(p.configured){const group=el('optgroup');group.label=p.name;
    const seen=new Set();for(const m of [{id:p.selectedModel,label:p.selectedModel},...(p.models||[])]){if(!m.id || seen.has(m.id))continue;seen.add(m.id);const o=option(`${p.id}::${m.id}`,m.label || m.id);o.dataset.model=m.id;o.dataset.provider=p.id;group.append(o);}models.push(group);}
  replace('model',models.length?models:[option('','Configure a provider')]);
  const matched=Array.from($('model').options).find(o=>o.value===current || o.dataset.model===current);if(matched)$('model').value=matched.value;
  $('selected-model').textContent=$('model').selectedOptions[0]?.dataset.model || 'No model selected';
}
function renderRuns(){
  const runs=state.runs.filter(r=>r.project===state.project);$('run-count').textContent=runs.length;
  replace('runs',runs.length?runs.map(r=>{const b=el('button',undefined,`run-row${r.id===state.run?' selected':''}`);b.append(el('strong',r.prompt),el('small',`${r.status} · ${new Date(r.created).toLocaleString()}`));b.onclick=()=>{state.run=r.id;showView('overview');renderRuns();};return b;}):[el('p','Your runs are saved here.','empty')]);
  const run=selectedRun();$('welcome').hidden=!!run;$('run-detail').hidden=!run;
  if(run){$('run-title').textContent=run.prompt;$('run-model').textContent=`${run.model} · ${run.mode}${run.rea_enabled?' · REA enabled':''}`;$('run-status').textContent=run.status;$('run-status').className=`badge ${run.status}`;$('reply').textContent=run.reply || (run.status==='running'?'Waiting for the model…':'');}
  const events=run?.events || [];$('event-count').textContent=events.length;
  const signature=`${run?.id}:${events.length}`;
  if($('console-activity').dataset.signature!==signature){$('console-activity').dataset.signature=signature;
    replace('console-activity',events.length?events.map(e=>{const n=el('details',undefined,'event'),s=el('summary');const detail=e.detail || {};s.append(el('time',new Date(e.time).toLocaleTimeString()),el('span',e.kind,'event-kind'),el('span',detail.path || detail.tool || detail.command || (detail.step?`Request ${detail.step}`:detail.model || '')));n.append(s,el('pre',JSON.stringify(detail,null,2)));return n;}):[el('p','Actual model requests, file actions and command results appear here.','empty')]);}
}
function updateControls(){
  const active=running();$('start').disabled=!state.project || !$('model').value || !!active || state.busy;$('stop').hidden=!active;$('stop').disabled=active?.status==='stopping';
  $('composer-hint').textContent=active?(active.status==='stopping'?'Stopping after the current model request or tool completes.':'Task running · actions appear in Activity'):(state.project?($('mode').value==='code'?'Code mode can edit files and run commands on this computer.':'Ask mode reads files. REA adds static analysis when enabled.'):'Open a project and choose a model.');
  $('status').textContent=active?`Run ${active.status}`:state.project?'Workspace ready':'Open a project';
  $('mode').disabled=!!active;$('model').disabled=!!active;$('rea-enabled').disabled=!!active;
}
async function selectProject(id){if(!guardDirty()){$('project').value=state.project;return;}state.project=id;localStorage.setItem('quixi.project',id);state.run='';state.file=null;state.dirty=false;state.rea.oracle=null;$('reconstruction-dossier').value='';$('oracle-result').hidden=true;renderEditor();renderProjects();renderRuns();updateControls();await loadFiles();await loadDossiers();}
async function loadFiles(){if(!state.project){replace('files',[el('p','Project files appear here.','empty')]);return;}
  const id=state.project,data=await pg('files',{query:$('filter').value});if(id!==state.project)return;state.files=data.files;state.git=data.git;renderFiles();renderGit();}
function renderFiles(){
  const files=state.files.filter(f=>!f.isDir).sort((a,b)=>a.relativePath.localeCompare(b.relativePath));
  replace('files',files.length?files.map(f=>{const b=el('button',undefined,`file-row${state.file?.path===f.relativePath?' selected':''}`);b.title=f.relativePath;const parent=f.relativePath.replaceAll('\\','/').split('/').slice(0,-1).join('/');b.append(el('span',(f.name.split('.').pop()||'TXT').slice(0,4).toUpperCase(),'file-ext'),el('span',parent?`${f.name} · ${parent}`:f.name));b.onclick=()=>openFile(f.relativePath).catch(error);return b;}):[el('p','No matching files.','empty')]);
}
function renderGit(){const g=state.git;const files=[...(g.modifiedFiles || []),...(g.untrackedFiles || [])];$('branch').textContent=g.isGitRepo?`${g.branch || 'HEAD'}${g.isDirty?' · modified':''}`:'No Git repository';$('change-count').textContent=new Set(files).size;replace('changed-files',[...new Set(files)].map(f=>el('span',f,'changed-file')));}
async function openFile(path){if(!guardDirty())return;requireProject();const data=await pg('read',{path});state.file=data;state.dirty=false;renderEditor();renderFiles();showView('code');}
function renderEditor(){const f=state.file;$('editor').disabled=!f;$('editor').value=f?.content || '';$('editor-path').textContent=f?.path || 'Select a file';updateEditor();}
function updateEditor(){const value=$('editor').value;$('dirty').hidden=!state.dirty;$('save').disabled=!state.file || !state.dirty;$('lines').textContent=Array.from({length:value.split('\n').length},(_,i)=>i+1).join('\n');$('file-stats').textContent=`UTF-8 · ${value.split('\n').length} lines · ${new Blob([value]).size.toLocaleString()} bytes`;}
async function saveFile(){if(!state.file || !state.dirty)return;const result=await pg('write',{path:state.file.path,content:$('editor').value,hash:state.file.hash});state.file={...state.file,content:$('editor').value,hash:result.hash};state.dirty=false;updateEditor();await loadFiles();}
async function loadDiff(){requireProject();const data=await pg('diff');state.git=data.git;renderGit();const diff=[data.diff,data.staged?'\n--- STAGED CHANGES ---\n'+data.staged:''].filter(Boolean).join('\n');replace('diff',(diff || 'No tracked file changes. New files are listed above.').split('\n').map(line=>el('span',line,line.startsWith('+')?'added':line.startsWith('-')?'removed':line.startsWith('@@')?'hunk':'')));}
async function startTask(e){e.preventDefault();requireProject();if(state.dirty)throw new Error('Save or discard the current editor changes before starting a task.');
  const chosen=$('model').selectedOptions[0];if(!chosen?.dataset.model)throw new Error('Configure a model provider first.');
  if($('rea-enabled').checked && !state.rea.connected)await connectRea();
  state.busy=true;updateControls();clearError();
  try{await providerApi('/complete-onboarding',{activeProvider:chosen.dataset.provider,activeModel:chosen.dataset.model});
    const result=await pg('run',{prompt:$('task').value,model:chosen.dataset.model,mode:$('mode').value,reaEnabled:$('rea-enabled').checked});state.run=result.id;showView('overview');await refreshState();
  }finally{state.busy=false;updateControls();}}
function providerFormData(){return{providerId:$('provider-id').value,baseUrl:$('base-url').value,apiKey:$('api-key').value,selectedModel:$('model-id').value,customModel:$('model-id').value,completeOnboarding:true};}
function fillProvider(){const p=(state.providers.providers || []).find(p=>p.id===$('provider-id').value);if(!p)return;$('base-url').value=p.baseUrl || '';$('api-key').value='';$('api-key').placeholder=p.apiKeyMasked || p.keyPlaceholder || 'Optional for local endpoints';$('model-id').value=p.selectedModel || '';replace('provider-models',(p.models || []).map(m=>option(m.id,m.label)));$('provider-message').textContent=p.lastTestedOk===true?'Last connection test succeeded.':'';}
function showProviders(){replace('provider-id',(state.providers.providers||[]).map(p=>option(p.id,p.name)));$('provider-id').value=state.providers.activeProvider || $('provider-id').value;fillProvider();$('provider-dialog').showModal();}

// REA: live catalog + availability, persistent artifact selection, full result history.
function unwrap(response){if(response?.structuredContent)return response.structuredContent;for(const c of response?.content || [])if(c.type==='text'){try{return JSON.parse(c.text);}catch{}}return response;}
function sessionResult(value){return value?.result || value;}
async function connectRea(){
  $('rea-health').textContent='Starting the bundled plugin and checking providers…';$('rea-health').classList.add('busy');
  try{const result=await pg('rea/connect',$('rea-runtime').value?{mode:$('rea-runtime').value}:{});$('rea-runtime').value=result.mode;state.rea.connected=true;state.rea.tools=result.tools || [];state.rea.session=result.session;state.rea.availability.clear();
    const session=sessionResult(result.session);for(const group of session.tool_availability?.groups || [])for(const name of group.names)state.rea.availability.set(name,group);
    const available=[...state.rea.availability.values()].filter(g=>g.available).length;
    const providers=session.analysis_provider_candidates || [];
    const ghidra=providers.find(p=>(p.id || p.provider_id || p.provider?.id)==='ghidra');
    const version=session.server_identity?.package_version || session.server_identity?.package?.version || session.server_identity?.version || '';
    $('rea-health').textContent=`REA ${version} (${result.mode}) connected · ${available} currently available tools / ${state.rea.tools.length} advertised.\n${session.path || session.target?.path || session.binary_path || 'Select an artifact and open it to enable target-specific tools.'}${ghidra?`\nGhidra: ${ghidra.availability?.status || String(ghidra.available ?? 'check tool availability')}`:''}`;
    $('rea-badge').textContent='Connected';$('rea-badge').className='badge completed';$('rea-connect').textContent='Refresh tools';renderTools();
  }catch(e){state.rea.connected=false;$('rea-badge').textContent='Unavailable';$('rea-badge').className='badge failed';$('rea-health').textContent=e.message;throw e;}finally{$('rea-health').classList.remove('busy');}
}
function renderTools(preferred){
  const old=preferred || $('rea-tool').value;const query=$('rea-search').value.trim().toLowerCase();
  const tools=state.rea.tools.filter(t=>!query || `${t.name} ${t.description}`.toLowerCase().includes(query));
  tools.sort((a,b)=>Number(!!state.rea.availability.get(b.name)?.available)-Number(!!state.rea.availability.get(a.name)?.available) || a.name.localeCompare(b.name));
  replace('rea-tool',tools.length?tools.map(t=>{const availability=state.rea.availability.get(t.name);const o=option(t.name,`${availability?.available?'●':'○'} ${t.name}`);o.title=availability?.remediation || '';return o;}):[option('','No matching tools')]);
  if(tools.some(t=>t.name===old))$('rea-tool').value=old;else if(tools.some(t=>t.name==='open_binary'))$('rea-tool').value='open_binary';
  toolChanged();
}
function toolChanged(){
  const tool=state.rea.tools.find(t=>t.name===$('rea-tool').value);const availability=state.rea.availability.get(tool?.name);
  $('rea-description').textContent=tool?.description || '';$('rea-schema').textContent=JSON.stringify(tool?.inputSchema || {},null,2);
  $('rea-availability').textContent=availability && !availability.available?`${availability.reason}: ${availability.remediation || 'Unavailable for this target or host.'}`:'';
  $('rea-run').disabled=!tool || availability?.available===false;
  const properties=tool?.inputSchema?.properties || {},args={};
  for(const key of ['path','input_path'])if(properties[key] && state.rea.target)args[key]=state.rea.target;
  if(properties.provider_id && tool.name==='open_binary' && $('rea-provider').value)args.provider_id=$('rea-provider').value;
  for(const key of tool?.inputSchema?.required || [])if(!(key in args)){
    const schema=properties[key] || {};args[key]=schema.default ?? schema.const ?? schema.enum?.[0] ?? (schema.type==='number'||schema.type==='integer'?0:schema.type==='boolean'?false:schema.type==='object'?{}:schema.type==='array'?[]:'');
  }
  if(properties.detail)args.detail='summary';
  if(properties.limit)args.limit=Math.min(Number(properties.limit.default)||50,50);
  $('rea-arguments').value=JSON.stringify(args,null,2);
}
async function loadAnalysisHistory(){const result=await pg('rea/inventory');state.rea.target=result.target || '';state.rea.targetIsDirectory=!!result.targetIsDirectory;state.rea.records=result.records || [];
  $('artifact-path').textContent=state.rea.target || 'EXE · DLL · .NET · ASAR · JavaScript · archives';$('artifact-path').title=state.rea.target;$('artifact-name').textContent=state.rea.target.split(/[\\/]/).pop() || 'Select an artifact';
  const old=$('rea-record').value;replace('rea-record',state.rea.records.length?state.rea.records.map(r=>option(r.id,`${r.failed?'Failed':'Result'} · ${r.tool} · ${new Date(r.created).toLocaleString()}`)):[option('','No analyses yet')]);if(state.rea.records.some(r=>r.id===old))$('rea-record').value=old;
  renderReconstruction();
  await loadDossiers();
}
async function selectArtifact(data){if(running())throw new Error('Finish the active task before changing its analysis target.');const result=await pg('rea/select',data);if(result.cancelled)return;await loadAnalysisHistory();toolChanged();}
async function runRea(e){e.preventDefault();const tool=$('rea-tool').value;let args;try{args=JSON.parse($('rea-arguments').value);}catch{throw new Error('Arguments must be valid JSON.');}
  if(!args || typeof args!=='object' || Array.isArray(args))throw new Error('Arguments must be a JSON object.');
  await busy($('rea-run'),async()=>{$('rea-health').textContent=`Running ${tool}… Native import and analysis can take several minutes.`;const record=await pg('rea/tool',{tool,arguments:args});await loadAnalysisHistory();$('rea-record').value=record.id;renderEvidence(record);await connectRea();},'Analysing…');
}
function collectValues(value, keys, found=[], depth=0){if(depth>14 || !value || typeof value!=='object')return found;for(const [key,v] of Object.entries(value)){if(keys.has(key))found.push(v);if(typeof v==='object')collectValues(v,keys,found,depth+1);}return found;}
function renderEvidence(record){
  state.rea.record=record;$('rea-export').disabled=false;$('rea-use').disabled=false;const value=unwrap(record.response);$('rea-output').textContent=JSON.stringify(record,null,2);$('evidence-raw').open=record.failed;
  const nodes=[el('h3',`${record.failed?'Analysis reported an error':'Analysis saved'} · ${record.tool}`),el('p',record.target || 'Session inspection','muted')];
  const ids=[...new Set(collectValues(value,new Set(['evidence_id','parent_evidence_id'])).filter(v=>typeof v==='string'))];
  if(ids.length)nodes.push(el('p',ids.join('\n'),'identity'));
  const limits=collectValues(value,new Set(['limitations','unknowns'])).flat().filter(v=>v!=null && (typeof v!=='string' || v));
  if(limits.length){const details=el('details');details.append(el('summary',`Limitations & unknowns (${limits.length})`));const ul=el('ul',undefined,'limitations');for(const v of limits)ul.append(el('li',typeof v==='string'?v:JSON.stringify(v)));details.append(ul);nodes.push(details);}
  const result=value?.result || value;const facts=Object.entries(result || {}).filter(([k,v])=>!['limitations','unknowns','evidence','graph','raw_result','tool_availability','server_identity','normalized_result'].includes(k) && (typeof v==='string' || typeof v==='number' || typeof v==='boolean'));
  for(const [k,v] of facts.slice(0,15))nodes.push(el('p',`${k.replaceAll('_',' ')}: ${String(v)}`));
  const failure=QuixiReconstruction.failure(record,value);
  if(failure){nodes.push(el('p',failure.message,'analysis-error'),el('p',failure.guidance,'field-note'));
    if(failure.nextTool){const b=el('button','Prepare native analysis','small');b.onclick=()=>prepareReaTool(failure.nextTool).catch(error);nodes.push(b);}}
  if(!record.failed && !facts.length && !limits.length && !ids.length)nodes.push(el('p','Open Complete result below to inspect the returned observations and metadata.','muted'));
  replace('evidence-summary',nodes);
  const code=collectValues(value,new Set(['pseudocode','pseudo_code','assembly','decompiled_code',...(/pseudo|assembly/.test(record.tool)?['normalized_result']:[])])).filter(v=>typeof v==='string' && v.trim()).join('\n\n');
  $('recovered-code').hidden=!code;$('recovered-code').textContent=code;
}

async function prepareReaTool(name){
  if(!state.rea.connected)await connectRea();
  if(!state.rea.tools.some(t=>t.name===name))throw new Error(`This REA version does not advertise ${name}. Refresh tools or choose another supported tool.`);
  $('rea-search').value='';renderTools(name);$('rea-arguments').focus();
  $('rea-health').textContent=`${name} selected. Review the arguments, then click Run analysis. Opening a native target uses Ghidra in the background.`;
}
function reconstructionInput(phase){
  const project=state.projects.find(p=>p.id===state.project);
  return {phase,target:state.rea.target,targetIsDirectory:state.rea.targetIsDirectory,project:project?.path || '',scope:$('reconstruction-scope').value,goal:$('reconstruction-goal').value,
    observations:$('reconstruction-observations').value,plan:QuixiReconstruction.plans(state.runs,state.project,state.rea.target).find(r=>r.id===$('reconstruction-plan').value),dossier:$('reconstruction-dossier').value,
    recordIds:state.rea.records.filter(r=>r.target===state.rea.target).map(r=>r.id)};
}
function renderReconstruction(){
  const old=$('reconstruction-plan').value,plans=QuixiReconstruction.plans(state.runs,state.project,state.rea.target);
  replace('reconstruction-plan',plans.length?plans.map(r=>option(r.id,`${new Date(r.created).toLocaleString()} · ${r.model}`)):[option('','No brief yet · prepare analysis first')]);
  if(plans.some(r=>r.id===old))$('reconstruction-plan').value=old;
  const project=state.projects.find(p=>p.id===state.project);
  $('reconstruction-destination').textContent=project?`Destination: ${project.path.replace(/^\\\\\?\\/, '')}. Use a separate project outside the original application.`:'Open a separate destination project with Open project.';
  $('reconstruction-build').disabled=(!plans.length && !$('reconstruction-dossier').value) || !!running();$('reconstruction-analyse').disabled=!!running();$('reconstruction-export').disabled=!!running() || !state.project || !state.rea.target;
  $('oracle-run').disabled=!!running() || !$('reconstruction-dossier').value;$('oracle-retry').disabled=!!running() || state.rea.oracle?.status!=='failed' || state.rea.oracle?.config!==`${$('reconstruction-dossier').value}/oracle-cases.json`;
}
async function loadDossiers(){
  const old=$('reconstruction-dossier').value,project=state.project;
  const result=project?await pg('reconstruction-inventory'):{dossiers:[]};if(project!==state.project)return;
  replace('reconstruction-dossier',[option('','New SPEC from selected brief'),...(result.dossiers || []).map(d=>option(d.path,`${new Date(d.created).toLocaleString()} · ${d.hasBrief?'SPEC saved':'draft without brief'}`))]);
  if(result.dossiers?.some(d=>d.path===old))$('reconstruction-dossier').value=old;renderReconstruction();
}
async function saveDossier(input){
  const result=await pg('reconstruction-export',{scope:input.scope,goal:input.goal,observations:input.observations,briefId:input.plan?.id});
  await loadDossiers();$('reconstruction-dossier').value=result.relativePath;renderReconstruction();await loadFiles();return result;
}
async function prepareReconstruction(phase){
  if(running())throw new Error('Finish the active task before preparing another.');
  const input=reconstructionInput(phase);if(phase==='retry')input.reportPath=state.rea.oracle?.reportPath;
  QuixiReconstruction.prompt(input);
  if(phase==='build' && !input.dossier){const saved=await saveDossier(input);input.dossier=saved.relativePath;}
  const prompt=QuixiReconstruction.prompt(input);
  if(phase==='plan' && !state.rea.connected)await connectRea();
  $('mode').value=phase==='plan'?'ask':'code';$('mode').dispatchEvent(new Event('change'));$('rea-enabled').checked=phase==='plan';
  $('task').value=prompt;state.run='';renderRuns();showView('overview');$('task').focus();updateControls();
}
async function loadToolchain(){
  const result=await pg('toolchain/inventory');
  replace('toolchain-list',result.tools.map(t=>{const row=el('section',undefined,'toolchain-row');row.append(el('strong',`${t.group} · ${t.name}`),el('p',t.status,'field-note'),el('p',t.note,'field-note'));
    if(t.path)row.append(el('p',t.path,'toolchain-path'));
    const actions=el('div',undefined,'reconstruction-actions');
    const action=(label,handler)=>{const b=el('button',label,'small');b.onclick=()=>handler().catch(error);actions.append(b);};
    action('Official instructions',()=>pg('toolchain/docs',{id:t.id}));
    if(!['reference','workflow','bundled'].includes(t.kind))action('Choose path…',async()=>{await pg('toolchain/configure',{id:t.id});await loadToolchain();});
    if(t.path && t.kind==='gui')action('Open tool',()=>pg('toolchain/open',{id:t.id}));
    if(t.path && ['cli','jar','python'].includes(t.kind))action('Prepare version check',async()=>{const r=await pg('toolchain/command',{id:t.id});$('toolchain-dialog').close();showView('overview');showConsole('terminal');$('terminal-command').value=r.command;});
    if(t.download && !t.path)action('Prepare portable install',async()=>{const r=await pg('toolchain/install-command',{id:t.id});$('toolchain-dialog').close();showView('overview');showConsole('terminal');$('terminal-command').value=r.command;});
    row.append(actions);return row;}));
}
let workflowOffset=0,workflowTotal=0;
async function readWorkflow(offset=0){const result=await pg('rea/workflow',{path:$('workflow-guide').value,offset});$('workflow-content').textContent=`${result.package} ${result.version}\n${result.note}\n\n${result.content}`;workflowOffset=result.nextOffset;workflowTotal=result.totalCharacters;$('workflow-next').disabled=workflowOffset>=workflowTotal;}

// Events
for(const b of document.querySelectorAll('[data-view]'))b.onclick=()=>showView(b.dataset.view);
for(const b of document.querySelectorAll('[data-console]'))b.onclick=()=>showConsole(b.dataset.console);
for(const b of document.querySelectorAll('[data-prompt]'))b.onclick=()=>{$('task').value=b.dataset.prompt;$('task').focus();};
for(const b of document.querySelectorAll('[data-rea-tool]'))b.onclick=()=>prepareReaTool(b.dataset.reaTool).catch(error);
on('reconstruction-analyse','click',()=>busy($('reconstruction-analyse'),()=>prepareReconstruction('plan'),'Preparing…'));on('reconstruction-build','click',()=>busy($('reconstruction-build'),()=>prepareReconstruction('build'),'Preparing…'));
on('reconstruction-export','click',()=>busy($('reconstruction-export'),async()=>{const input=reconstructionInput('plan');QuixiReconstruction.prompt(input);const result=await saveDossier(input);$('reconstruction-status').textContent=`Saved SPEC.md, oracle-cases.json and ${result.records} analysis records to ${result.path}`;},'Saving dossier…'));
on('reconstruction-dossier','change',()=>{state.rea.oracle=null;$('oracle-result').hidden=true;renderReconstruction();});
on('oracle-run','click',()=>busy($('oracle-run'),async()=>{if($('mode').value!=='code')throw new Error('Select Code mode in the sidebar to execute the reviewed oracle commands.');const result=await pg('oracle-run',{mode:'code',config:`${$('reconstruction-dossier').value}/oracle-cases.json`});state.rea.oracle=result;$('oracle-result').hidden=false;$('oracle-result').textContent=JSON.stringify(result,null,2);renderReconstruction();await loadFiles();},'Running checks…'));
on('oracle-retry','click',()=>prepareReconstruction('retry'));
on('toolchain-open','click',async()=>{$('toolchain-dialog').showModal();await loadToolchain();});on('toolchain-close','click',()=>$('toolchain-dialog').close());on('toolchain-refresh','click',loadToolchain);
on('rea-restart','click',()=>busy($('rea-restart'),async()=>{if(running())throw new Error('Finish the active task before restarting its analysis plugin.');await pg('rea/disconnect');state.rea.connected=false;await connectRea();},'Restarting…'));
on('workflow-read','click',()=>readWorkflow());on('workflow-next','click',()=>readWorkflow(workflowOffset));on('workflow-guide','change',()=>{$('workflow-next').disabled=true;});
on('rea-provider','change',toolChanged);
on('theme','click',()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;localStorage.setItem('quixi.theme',theme);});
on('explorer-toggle','click',()=>$('explorer').classList.toggle('show'));on('settings-toggle','click',()=>$('settings').classList.toggle('show'));
on('open-project','click',()=>busy($('open-project'),async()=>{if(!guardDirty())return;const project=await pg('project');if(!project.cancelled){await refreshState();await selectProject(project.id);}}));
on('project','change',()=>selectProject($('project').value));on('refresh','click',loadFiles);let filterTimer;on('filter','input',()=>{clearTimeout(filterTimer);filterTimer=setTimeout(()=>loadFiles().catch(error),180);});
on('new-file','click',async()=>{requireProject();if(!guardDirty())return;const path=await askText('Create a file','Path relative to the selected project');if(!path)return;state.file={path,content:'',hash:''};state.dirty=true;renderEditor();showView('code');$('editor').focus();});
on('editor','input',()=>{state.dirty=!!state.file && $('editor').value!==state.file.content;updateEditor();});on('editor','scroll',()=>$('lines').scrollTop=$('editor').scrollTop);
on('editor','keydown',e=>{if(e.key==='Tab'){e.preventDefault();const t=e.target,start=t.selectionStart;t.setRangeText('    ',start,t.selectionEnd,'end');t.dispatchEvent(new Event('input'));}});
on('save','click',()=>busy($('save'),saveFile,'Saving…'));on('refresh-diff','click',loadDiff);
on('console-expand','click',()=>$('console').classList.toggle('expanded'));
on('new-run','click',()=>{state.run='';$('task').value='';showView('overview');renderRuns();$('task').focus();});on('task-form','submit',startTask);
on('stop','click',async()=>{const active=running();if(active){await pg('cancel',{id:active.id});await refreshState();}});
on('mode','change',()=>{$('access-note').textContent=$('mode').value==='code'?'Code mode can edit files and run commands with your Windows user permissions.':'Ask mode can inspect project files and answer questions.';updateControls();});
on('model','change',()=>{localStorage.setItem('quixi.model',$('model').value);$('selected-model').textContent=$('model').selectedOptions[0]?.dataset.model || '';updateControls();});
on('terminal-form','submit',async e=>{e.preventDefault();requireProject();const command=$('terminal-command').value.trim();if(!command)return;await busy($('terminal-send'),async()=>{const result=await pg('command',{command});$('terminal-output').textContent=`› ${command}\n${result.stdout || ''}${result.stderr || ''}\nExit code: ${result.exitCode}${result.timedOut?' (timed out)':''}`;$('terminal-command').value='';await loadFiles();});});
on('providers','click',showProviders);on('configure','click',showProviders);on('close-provider','click',()=>$('provider-dialog').close());on('provider-id','change',fillProvider);
on('provider-form','submit',async e=>{e.preventDefault();await providerApi('/save',providerFormData());$('api-key').value='';await refreshState();$('provider-dialog').close();});
on('test-provider','click',()=>busy($('test-provider'),async()=>{const result=await providerApi('/test',providerFormData());$('provider-message').textContent=`${result.ok?'Connected':'Connection failed'}: ${result.message || JSON.stringify(result)}`;if(result.discoveredModels)replace('provider-models',result.discoveredModels.map(m=>option(m,m)));},'Testing…'));
on('detect-local','click',()=>busy($('detect-local'),async()=>{const result=await providerApi('/detect-local',{});$('provider-message').textContent=JSON.stringify(result,null,2);await refreshState();},'Detecting…'));
on('open-bench','click',()=>pg('open-bench'));
on('show-analysis','click',()=>showView('analysis'));on('rea-connect','click',()=>busy($('rea-connect'),connectRea,'Connecting…'));
on('rea-runtime','change',()=>busy($('rea-connect'),connectRea,'Connecting…'));
on('artifact-file','click',()=>selectArtifact({}));on('artifact-folder','click',()=>selectArtifact({directory:true}));on('artifact-set-path','click',async()=>{const path=await askText('Select an artifact','Absolute path to a file or application folder',state.rea.target);if(path)await selectArtifact({path});});
on('rea-search','input',()=>renderTools());on('rea-tool','change',toolChanged);on('rea-form','submit',runRea);
on('rea-close','click',async()=>{if(!state.rea.connected)return;const record=await pg('rea/tool',{tool:'close_binary',arguments:{}});await loadAnalysisHistory();$('rea-record').value=record.id;renderEvidence(record);await connectRea();});
on('rea-record','change',async()=>{if($('rea-record').value)renderEvidence(await pg('rea/evidence',{id:$('rea-record').value}));});
on('rea-use','click',()=>{if(!state.rea.record)return;const r=state.rea.record;$('rea-enabled').checked=true;$('task').value=`Use the saved REA analysis record ${r.id} (${r.tool}) for ${r.target}. Explain the observed behaviour, cite Evidence IDs, distinguish inferences and limitations, and suggest the next implementation step in this project.`;showView('overview');$('task').focus();});
on('rea-export','click',async()=>{if(!state.rea.record)return;const result=await pg('rea/export',{id:state.rea.record.id});if(result.path)$('rea-health').textContent=`Evidence exported to ${result.path}`;});
on('rea-enabled','change',async()=>{if($('rea-enabled').checked){try{if(!state.rea.connected)await connectRea();}catch(e){$('rea-enabled').checked=false;throw e;}}});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();saveFile().catch(error);}if((e.ctrlKey||e.metaKey)&&e.key==='Enter' && !document.querySelector('dialog[open]')){e.preventDefault();if(!$('start').disabled)$('task-form').requestSubmit();}});
window.addEventListener('beforeunload',e=>{if(state.dirty){e.preventDefault();e.returnValue='';}});
document.documentElement.dataset.theme=localStorage.getItem('quixi.theme') || 'dark';
(async()=>{try{await refreshState();await loadFiles();await loadAnalysisHistory();}catch(e){error(e);$('connection').classList.add('offline');$('connection').textContent='Disconnected';}
  async function poll(){try{const previous=running();await refreshState();if(previous && !running()){await loadFiles();await loadAnalysisHistory();}}catch(e){$('connection').classList.add('offline');$('connection').textContent='Disconnected';}finally{setTimeout(poll,running()?1200:7000);}}setTimeout(poll,7000);
})();
