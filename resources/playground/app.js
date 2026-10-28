/* REA Studio's native playground. All workspace and analysis results come from Rust APIs. */
'use strict';
const $ = id => document.getElementById(id);
const state = { projects: [], runs: [], providers: {}, project: localStorage.getItem('quixi.project') || '',
  run: '', file: null, dirty: false, files: [], git: {}, rea: {connected:false, tools:[], availability:new Map(), records:[], target:'', nav:{items:[],index:-1}, current:null, procs:new Map(), addresses:new Map(), opened:new Set(), hint:null, oracleInfo:null}, busy:false };
const el = (tag, text, className) => { const n=document.createElement(tag); if(text!==undefined)n.textContent=text; if(className)n.className=className; return n; };
const replace = (id, children) => $(id).replaceChildren(...children);
const option = (value,label) => {const n=el('option',label);n.value=value;return n;};
function error(e) { $('error').textContent=e?.message || String(e); $('error').hidden=false; }
function clearError() { $('error').hidden=true; }
async function api(route, data, prefix='/api/quixi/playground/') {
  const response=await fetch(prefix+route,{method:data===undefined?'GET':'POST',headers:data===undefined?{}:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});
  const fail=message=>Object.assign(new Error(message),{status:response.status});
  if(!/\bjson\b/i.test(response.headers.get('content-type') || '')){const text=(await response.text().catch(()=>'')).trim().slice(0,300);throw fail(`${route} · ${response.status} ${text || response.statusText || 'Unexpected response'}`);}
  const result=await response.json();
  if(!response.ok || result.error)throw fail(result.error || `Request failed: ${response.status}`);
  return result;
}
// A route this build does not provide: HTTP 404 or the engine's "Unknown … operation" error
// (real errors such as "Task not found in this project" are not treated as missing routes).
const unsupported=e=>e?.status===404 || /^Unknown [\w ]*operation$/i.test(e?.message || '');
const show=QuixiAnalysis.visible;
// Rebuild a <select> only when its options changed and the user is not interacting with it.
function replaceSelect(id,nodes){
  const s=$(id),label=n=>`${n.value}|${n.textContent}|${n.disabled?1:0}`;
  const signature=nodes.map(n=>n.tagName==='OPTGROUP'?`[${n.label}:${Array.from(n.children,label).join('\n')}]`:label(n)).join('\n');
  if(s.dataset.signature===signature || document.activeElement===s)return false;
  s.replaceChildren(...nodes);s.dataset.signature=signature;return true;
}
function setSelect(id,value){if(document.activeElement!==$(id))$(id).value=value;}
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
  window.QuixiWorkflow?.viewChanged(view);
  if(view==='changes' && state.project)loadDiff().catch(error);
  if(view==='analysis'){loadAnalysisHistory().catch(error);refreshAnalysisSources().catch(error);loadRuntimeSettings().catch(error);window.QuixiInvestigations?.refresh().catch(error);}
}
function showConsole(name) {
  document.querySelectorAll('[data-console]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.console===name)));
  ['activity','terminal'].forEach(n=>$(`console-${n}`).hidden=n!==name);
}
function selectedRun(){return state.runs.find(r=>r.id===state.run);}
function running(){return state.runs.find(r=>QuixiAnalysis.activeRunStatuses.includes(r.status));}
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
  renderProjects();renderModels();renderRuns();updateControls();renderReconstruction();updateAnalysisControls();
  if($('mcp-dialog').open)await refreshMcp();
  return data;
}
function renderProjects(){
  replaceSelect('project',[option('','Select a project'),...state.projects.map(p=>option(p.id,p.name))]);setSelect('project',state.project);
  const p=state.projects.find(p=>p.id===state.project);$('project-name').textContent=p?.name || 'Your coding workspace';$('project-path').textContent=p?.path?.replace(/^\\\\\?\\/, '') || 'Open a local project to get started';
  $('project-path').title=p?.path || '';
  renderReceivedCode();
}
function receivedSeen(){try{return JSON.parse(localStorage.getItem('quixi.received-seen') || '[]');}catch{return [];}}
function pendingCode(){const seen=receivedSeen();return state.projects.filter(p=>p.received && !seen.includes(p.id)).at(-1);}
function markReceivedSeen(id){localStorage.setItem('quixi.received-seen',JSON.stringify([...new Set([...receivedSeen(),id])]));renderReceivedCode();}
function renderReceivedCode(){const p=pendingCode();$('received-code').hidden=!p;if(p)$('received-code-note').textContent=`Agent sent ${p.name} · ${p.received.fileCount} file(s) for ${p.received.purpose}.`;}
function renderModels(){
  const current=$('model').value || localStorage.getItem('quixi.model') || state.providers.activeModel;
  const models=[];
  for(const p of state.providers.providers || [])if(p.configured){const group=el('optgroup');group.label=p.name;
    const seen=new Set();for(const m of [{id:p.selectedModel,label:p.selectedModel},...(p.models||[])]){if(!m.id || seen.has(m.id))continue;seen.add(m.id);const o=option(`${p.id}::${m.id}`,m.label || m.id);o.dataset.model=m.id;o.dataset.provider=p.id;group.append(o);}models.push(group);}
  replaceSelect('model',models.length?models:[option('','Add a connection first')]);
  const choices=Array.from($('model').options);
  const matched=choices.find(o=>o.value===current) || choices.find(o=>o.dataset.model===current && o.dataset.provider===state.providers.activeProvider)
    || choices.find(o=>o.dataset.provider===state.providers.activeProvider && o.dataset.model===state.providers.activeModel)
    || choices.find(o=>o.dataset.provider===state.providers.activeProvider && o.dataset.model===(state.providers.providers || []).find(p=>p.id===state.providers.activeProvider)?.selectedModel);
  if(matched){setSelect('model',matched.value);localStorage.setItem('quixi.model',matched.value);}
  $('selected-model').textContent=$('model').selectedOptions[0]?.dataset.model || 'No model selected';
  renderHelper();
}
function renderRuns(){
  const all=state.runs.filter(r=>r.project===state.project),runs=all.filter(r=>QuixiAnalysis.runMatches(r,$('run-filter').value));$('run-count').textContent=all.length;
  replace('runs',runs.length?runs.map(r=>{const b=el('button',undefined,`run-row${r.id===state.run?' selected':''}`),waiting=r.status==='awaiting_approval';b.append(el('strong',r.prompt),el('small',`${waiting?'awaiting approval':r.status} · ${new Date(r.created).toLocaleString()}`));if(waiting)b.append(el('span','Needs your approval','badge awaiting'));b.onclick=()=>{state.run=r.id;showView('overview');renderRuns();};return b;}):[el('p',all.length?'No runs match this search.':'Your runs are saved here.','empty')]);
  const run=selectedRun();$('welcome').hidden=!!run;$('run-detail').hidden=!run;
  if(run){$('run-title').textContent=run.prompt;$('run-model').textContent=QuixiAnalysis.runMeta(run);$('run-status').textContent=run.status==='awaiting_approval'?'awaiting approval':run.status;$('run-status').className=`badge ${run.status}`;$('reply').textContent=run.reply || (QuixiAnalysis.activeRunStatuses.includes(run.status)?'Waiting for the model…':'');renderRunExtras(run);}
  const events=run?.events || [];$('event-count').textContent=events.length;
  // Append only new events so open entries stay open; a different run starts a fresh list.
  if(activity.run!==(run?.id || '') || events.length<activity.count){activity.run=run?.id || '';activity.count=0;replace('console-activity',[el('p','Actual model requests, file actions and command results appear here.','empty')]);}
  if(events.length>activity.count){if(!activity.count)$('console-activity').replaceChildren();$('console-activity').append(...events.slice(activity.count).map(eventNode));activity.count=events.length;}
}
// Run detail extras: parent run, command approval, follow-up and the run's own change set.
const runView={approval:'',command:'',changes:'',run:'',pending:null};
function renderRunExtras(run){
  const parent=run.parentRun && state.runs.find(r=>r.id===run.parentRun);$('run-parent').hidden=!run.parentRun;
  if(run.parentRun){const link=el('button',parent?parent.prompt:run.parentRun,'link');link.type='button';link.onclick=()=>{if(parent){state.run=parent.id;renderRuns();}};$('run-parent').replaceChildren(document.createTextNode('Continues '),link);}
  $('run-continue').hidden=QuixiAnalysis.activeRunStatuses.includes(run.status);
  const waiting=run.status==='awaiting_approval',pending=QuixiAnalysis.pendingCommand(run.pendingCommand),signature=waiting?`${run.id}|${pending.command}|${pending.detail}`:'';
  $('run-approval').hidden=!waiting;
  // The raw command shown to the user; approve/deny send it so a changed command is never answered unseen.
  if(signature!==runView.approval){runView.approval=signature;runView.command=typeof run.pendingCommand?.command==='string'?run.pendingCommand.command:'';$('approval-command').textContent=pending.command || 'The run did not report the command.';$('approval-detail').textContent=pending.detail;$('approval-detail').hidden=!pending.detail;$('approval-reason').value='';}
  renderRunChanges(run);
}
function renderRunChanges(run){
  const changes=Array.isArray(run.changes)?run.changes:[],locked=!!running(),signature=JSON.stringify([run.id,changes,locked]);
  $('run-changes-panel').hidden=!changes.length;if(signature===runView.changes)return;runView.changes=signature;
  if(runView.run!==run.id){runView.run=run.id;runView.pending=null;$('run-revert-confirm').hidden=true;$('run-changes-message').textContent='';$('run-diff').hidden=$('run-diff-title').hidden=$('run-diff-more').hidden=true;}
  $('run-changes-count').textContent=changes.length;$('run-revert-all').disabled=locked;
  replace('run-changes',changes.map(c=>{
    const row=el('div',undefined,'run-change'),name=el('button',show(c.path),'link');name.type='button';name.title='Show what this run changed in the file';name.onclick=()=>showRunDiff(run.id,c.path).catch(error);
    const revert=el('button','Revert this file','small');revert.type='button';revert.disabled=locked || !!c.reverted;if(c.reverted)revert.title='Already reverted';revert.onclick=()=>busy(revert,()=>revertRun(run.id,[c.path]),'Reverting…').catch(error);
    row.append(name,...[c.created && 'created',c.deleted && 'deleted',c.reverted && 'reverted',c.conflict && 'conflict'].filter(Boolean).map(t=>el('span',t,`badge${t==='conflict'?' failed':''}`)),revert);return row;}));
}
async function runRoute(route,data,missing){try{return await pg(route,data);}catch(e){if(unsupported(e))throw new Error(missing);throw e;}}
async function showRunDiff(id,path){
  const result=await runRoute('run-diff',{id,path},'This build cannot show per-run diffs yet.');
  $('run-diff-title').textContent=`What this run changed in ${show(path)}`;$('run-diff-title').hidden=false;$('run-diff').hidden=false;renderDiff('run-diff',result.diff || 'No differences.',!!result.truncated);
}
async function revertRun(id,paths,force=false){
  const result=await runRoute('run-revert',{id,...(paths?{paths}:{}),...(force?{force:true}:{})},'This build cannot revert run changes yet.');
  const reverted=result.reverted || [],skipped=result.skipped || [],forceable=QuixiAnalysis.forceableSkips(skipped),settled=skipped.length-forceable.length;
  $('run-changes-message').textContent=`${reverted.length} file${reverted.length===1?'':'s'} reverted${skipped.length?` · ${skipped.length} skipped`:''}${settled?` (${settled} already reverted or not changed by this run)`:''}.`;
  // Forcing cannot help files that are already reverted, so only offer it for the others.
  if(forceable.length && !force){runView.pending={id,paths:forceable.map(s=>s.path)};
    replace('run-revert-skipped',forceable.map(s=>{const li=el('li');li.append(el('code',show(s.path)),document.createTextNode(` · ${show(s.reason || 'skipped')}`));return li;}));$('run-revert-confirm').hidden=false;$('run-revert-cancel').focus();}
  else{runView.pending=null;$('run-revert-confirm').hidden=true;}
  await refreshState();await loadFiles();if(state.file && reverted.some(p=>p===state.file.path))await checkDisk();
}
function renderContinue(){const parent=state.runs.find(r=>r.id===state.continueFrom);$('continue-chip').hidden=!parent;if(parent)$('continue-label').textContent=`Continues: ${parent.prompt}`;else state.continueFrom='';}
const activity={run:null,count:0};
function eventNode(e){
  const n=el('details',undefined,'event'),s=el('summary'),detail=e.detail || {};
  s.append(el('time',new Date(e.time).toLocaleTimeString()),el('span',e.kind,'event-kind'),el('span',show(detail.path || detail.tool || detail.command || (detail.step?`Request ${detail.step}`:detail.model || ''))));
  n.append(s);n.addEventListener('toggle',()=>{if(n.open && !n.querySelector('pre'))n.append(el('pre',JSON.stringify(detail,null,2)));});return n;
}
function updateControls(){
  const active=running(),waiting=active?.status==='awaiting_approval';$('start').disabled=!state.project || !$('model').value || !!active || state.busy || !!state.rea.operation || !!state.rea.connecting || !!state.rea.oracleOperation || !!window.QuixiInvestigations?.busy;$('stop').hidden=!active;$('stop').disabled=active?.status==='stopping';
  $('project').disabled=!!state.rea.oracleOperation || !!window.QuixiInvestigations?.busy;
  $('composer-hint').textContent=active?(waiting?'The agent is waiting for you to approve a command · open the run to decide.':active.status==='stopping'?'Stopping after the current model request or tool completes.':'Task running · actions appear in Activity'):(state.project?($('mode').value==='code'?'Code mode can edit files and run commands on this computer.':'Ask mode reads files. REA adds static analysis when enabled.'):'Open a project and choose a model.');
  $('status').textContent=active?(waiting?'Run awaiting your approval':`Run ${active.status}`):state.project?'Workspace ready':'Open a project';$('status').classList.toggle('attention',!!waiting);
  $('mode').disabled=!!active;$('model').disabled=!!active;$('rea-enabled').disabled=!!active;$('max-steps').disabled=!!active;$('confirm-commands').disabled=!!active;
  $('received-code-open').disabled=!!active || !!state.rea.operation;
  window.QuixiWorkflow?.updateTaskContext();
}
async function selectProject(id){if(state.rea.oracleOperation || window.QuixiInvestigations?.busy){$('project').value=state.project;throw new Error('Finish the current oracle or investigation operation before switching projects.');}if(!guardDirty()){$('project').value=state.project;return false;}state.project=id;localStorage.setItem('quixi.project',id);state.run='';state.file=null;state.dirty=false;state.continueFrom='';renderContinue();state.rea.oracle=null;gitView.files=null;gitView.selected='';$('reconstruction-dossier').value='';$('oracle-result').hidden=true;renderEditor();renderProjects();renderRuns();updateControls();renderTerminal();window.dispatchEvent(new Event('rea-project-changed'));await loadFiles();await loadDossiers();if(state.projects.find(p=>p.id===id)?.received)markReceivedSeen(id);return true;}
async function loadFiles(){if(!state.project){replace('files',[el('p','Project files appear here.','empty')]);return;}
  const id=state.project,t=fileSeq.next(),data=await pg('files',{query:$('filter').value});if(id!==state.project || !fileSeq.current(t))return;state.files=data.files;state.git=data.git;renderFiles();renderGit();}
const fileSeq=QuixiAnalysis.sequencer();
function renderFiles(){
  const files=state.files.filter(f=>!f.isDir).sort((a,b)=>a.relativePath.localeCompare(b.relativePath));
  replace('files',files.length?files.map(f=>{const b=el('button',undefined,`file-row${state.file?.path===f.relativePath?' selected':''}`);b.title=f.relativePath;const parent=f.relativePath.replaceAll('\\','/').split('/').slice(0,-1).join('/');b.append(el('span',(f.name.split('.').pop()||'TXT').slice(0,4).toUpperCase(),'file-ext'),el('span',parent?`${f.name} · ${parent}`:f.name));b.onclick=()=>openFile(f.relativePath).catch(error);return b;}):[el('p','No matching files.','empty')]);
}
// Detailed per-file rows replace the chips once the diff route reports files.
function renderGit(){const g=state.git;const files=[...(g.modifiedFiles || []),...(g.untrackedFiles || [])];$('branch').textContent=g.isGitRepo?`${g.branch || 'HEAD'}${g.isDirty?' · modified':''}`:g.disabledReason?'Git disabled for this project':'No Git repository';$('branch').title=g.disabledReason || '';$('change-count').textContent=new Set(files).size;if(!gitView.files)replace('changed-files',[...new Set(files)].map(f=>el('span',f,'changed-file')));}
// Editor: LF-only buffer; the file's line endings and BOM travel with it and are restored on write.
const editorState={saving:false,queued:false};
function loadEditorFile(data,keep=false){
  const e=$('editor'),pos=[e.selectionStart,e.selectionEnd,e.scrollTop];
  state.file={...data,content:QuixiAnalysis.normalizeEol(data.content)};state.dirty=false;disk.pending=null;$('disk-bar').hidden=true;$('disk-diff-output').hidden=true;renderEditor();
  if(keep){const n=e.value.length;e.setSelectionRange(Math.min(pos[0],n),Math.min(pos[1],n));e.scrollTop=pos[2];$('lines').scrollTop=pos[2];}
}
async function openFile(path){if(!guardDirty())return;requireProject();const data=await pg('read',{path});loadEditorFile(data);renderFiles();showView('code');}
function renderEditor(){const f=state.file;$('editor').disabled=!f;$('editor').value=f?.content || '';$('editor-path').textContent=f?.path || 'Select a file';updateEditor();editorStats();}
// Line numbers and byte counts are throttled and the gutter only rebuilds when the line count changes.
let editorTimer=0,lineCount=0;
function updateEditor(){$('dirty').hidden=!state.dirty;$('save').disabled=!state.file || !state.dirty || editorState.saving;$('save').title=editorState.saving?'Saving…':'';clearTimeout(editorTimer);editorTimer=setTimeout(editorStats,150);}
function editorStats(){
  const value=$('editor').value;let count=1;for(let i=value.indexOf('\n');i!==-1;i=value.indexOf('\n',i+1))count++;
  if(count!==lineCount){lineCount=count;$('lines').textContent=Array.from({length:count},(_,i)=>i+1).join('\n');$('lines').scrollTop=$('editor').scrollTop;}
  $('file-stats').textContent=`${QuixiAnalysis.fileFormat(state.file)} · ${count} lines · ${new Blob([value]).size.toLocaleString()} bytes`;
}
// One save at a time: the snapshot taken before the request is what is marked saved; Ctrl+S during a save queues one more.
async function saveFile(opts={}){
  const file=state.file;if(!file || (!state.dirty && !opts.hash))return;
  if(editorState.saving){editorState.queued=true;return;}
  editorState.saving=true;clearError();updateEditor();
  const content=$('editor').value;let saved=false;
  try{
    const result=await pg('write',{path:file.path,content,hash:opts.hash ?? file.hash,lineEnding:file.lineEnding || 'lf',bom:!!file.bom});
    if(state.file!==file)return;
    state.file={...file,content,hash:result.hash,...(result.lineEnding?{lineEnding:result.lineEnding}:{}),...(typeof result.bom==='boolean'?{bom:result.bom}:{})};
    state.dirty=$('editor').value!==content;disk.pending=null;$('disk-bar').hidden=true;$('disk-diff-output').hidden=true;saved=true;
  }finally{
    editorState.saving=false;updateEditor();
    if(editorState.queued){editorState.queued=false;if(state.dirty && state.file?.path===file.path)saveFile().catch(error);}
  }
  if(saved)await loadFiles();
}
// B4: the open file is re-read after polls and run steps; clean buffers follow the disk, edited ones ask.
const disk={checking:false,pending:null};
async function checkDisk(){
  const file=state.file,project=state.project;if(!file?.hash || !project || disk.checking || editorState.saving)return;
  disk.checking=true;
  try{const data=await pg('read',{path:file.path});
    if(state.file!==file || state.project!==project || data.hash===file.hash)return;
    if(!state.dirty){loadEditorFile(data,true);return;}
    if(disk.pending?.hash!==data.hash){disk.pending=data;$('disk-diff-output').hidden=true;}
    $('disk-bar').hidden=false;
  }catch{/* Deleted, renamed or unreadable files keep the buffer; Save reports the conflict. */}
  finally{disk.checking=false;}
}
async function loadDiff(){requireProject();
  const g=state.git || {};
  if(g.disabledReason || g.isGitRepo===false){notGit(g.disabledReason?`Git is disabled for this project: ${g.disabledReason}`:'Not a Git repository. Open a folder under Git to review its changes here.');return;}
  let data;try{data=await pg('diff');}catch(e){if(/not a git repository/i.test(e.message)){notGit('Not a Git repository. Open a folder under Git to review its changes here.');return;}throw e;}
  if(data.git)state.git=data.git;gitView.files=Array.isArray(data.files)?data.files:null;gitView.selected='';
  $('changes-note').textContent='Tracked changes and new files in this project’s Git working tree.';renderGit();renderGitFiles();$('commit-form').hidden=!gitView.files;
  const diff=[data.diff,data.staged?'\n--- STAGED CHANGES ---\n'+data.staged:''].filter(Boolean).join('\n');
  $('diff-title').textContent=gitView.files?'All changes · select a file to see only its diff.':'';renderDiff('diff',diff || 'No tracked file changes. New files are listed above.',!!data.truncated);
}
function notGit(message){gitView.files=null;$('changes-note').textContent=message;replace('changed-files',[]);$('commit-form').hidden=true;$('discard-confirm').hidden=true;$('diff-title').textContent='';renderDiff('diff','',false);$('diff').textContent='';}
// Large diffs render 5,000 lines at a time.
const diffPages={};
function renderDiff(id,text,truncated,append=false){
  const page=append?diffPages[id]:(diffPages[id]={text,offset:0,truncated});const view=QuixiAnalysis.diffLines(page.text,page.offset);
  const nodes=view.lines.map(l=>el('span',l.text,l.cls));if(view.next===null && page.truncated)nodes.push(el('span','[Diff truncated by REA Studio · use your Git client for the rest]','hunk'));
  if(append)$(id).append(...nodes);else $(id).replaceChildren(...nodes);
  page.offset=view.next ?? view.total;$(`${id}-more`).hidden=view.next===null;if(view.next!==null)$(`${id}-more`).textContent=`Show more · ${(view.total-view.next).toLocaleString()} more lines`;
}
const gitView={files:null,selected:'',discard:null};
const gitKey=f=>`${f.staged?'S':'W'}:${f.path}`;
function renderGitFiles(){
  if(!gitView.files)return;
  replace('changed-files',gitView.files.length?gitView.files.map(f=>{
    const l=QuixiAnalysis.gitFileLabel(f),row=el('div',undefined,`git-file${gitView.selected===gitKey(f)?' selected':''}`),open=el('button',undefined,'git-file-name');open.type='button';open.title=`Show the diff for ${f.path}`;
    open.append(el('span',l.letter,`git-status s-${l.letter}`),el('span',show(f.path)));open.onclick=()=>showFileDiff(f).catch(error);
    const act=(label,task,cls='small')=>{const b=el('button',label,cls);b.type='button';b.onclick=()=>busy(b,task).catch(error);return b;};
    row.append(open,el('span',l.counts,'git-counts'),...(f.staged?[el('span','staged','badge completed')]:[]),
      f.staged?act('Unstage',()=>gitAction('git-unstage',{paths:[f.path]})):act('Stage',()=>gitAction('git-stage',{paths:[f.path]})),act('Discard',async()=>askDiscard([f.path]),'small danger'));
    return row;}):[el('p','No changes in the working tree.','muted')]);
}
async function gitAction(route,data){
  try{await pg(route,data);}catch(e){if(unsupported(e))throw new Error('This build cannot change the Git working tree from REA Studio yet.');throw e;}
  await loadFiles();await loadDiff();
}
async function showFileDiff(f){
  let result;try{result=await pg('diff-file',{path:f.path,staged:!!f.staged});}catch(e){if(unsupported(e))throw new Error('This build shows the combined diff only.');throw e;}
  gitView.selected=gitKey(f);renderGitFiles();$('diff-title').textContent=`${f.staged?'Staged':'Working tree'} diff · ${show(f.path)}`;renderDiff('diff',result.diff || 'No differences.',!!result.truncated);
}
function askDiscard(paths){gitView.discard=paths;$('discard-note').textContent=`Discard all uncommitted changes to ${paths.map(p=>show(p)).join(', ')}? The working tree copy is restored from Git and this cannot be undone.`;$('discard-confirm').hidden=false;$('discard-cancel').focus();}
async function startTask(e){e.preventDefault();requireProject();if(state.rea.operation || state.rea.connecting)throw new Error('Finish the active analysis first.');if(state.dirty)throw new Error('Save or discard the current editor changes before starting a task.');
  const chosen=$('model').selectedOptions[0];if(!chosen?.dataset.model)throw new Error('Choose the Agent model in the Models card first.');
  const maxSteps=Number($('max-steps').value);if(!Number.isInteger(maxSteps) || maxSteps<1 || maxSteps>100)throw new Error('Max steps must be a whole number from 1 to 100.');
  if($('rea-enabled').checked && !state.rea.connected)await connectRea();
  state.busy=true;updateControls();clearError();
  try{await providerApi('/complete-onboarding',{activeProvider:chosen.dataset.provider,activeModel:chosen.dataset.model});
    const parent=state.runs.find(r=>r.id===state.continueFrom && r.project===state.project);
    const result=await pg('run',{prompt:$('task').value,provider:chosen.dataset.provider,model:chosen.dataset.model,mode:$('mode').value,reaEnabled:$('rea-enabled').checked,maxSteps,confirmCommands:$('confirm-commands').value,...(parent?{parentRun:parent.id}:{})});
    state.run=result.id;state.continueFrom='';renderContinue();showView('overview');await refreshState();
  }finally{state.busy=false;updateControls();}}
// Saving a connection only becomes the active Agent model when none is chosen yet; roles are picked in the Models card.
function providerFormData(){const contextWindow=Number($('provider-context-window').value);if(!Number.isInteger(contextWindow) || contextWindow<1024 || contextWindow>2000000)throw new Error('Server context capacity must be between 1,024 and 2,000,000 tokens.');return{contextWindow,providerId:$('provider-id').value,baseUrl:$('base-url').value,apiKey:$('api-key').value,selectedModel:$('model-id').value.trim(),customModel:$('model-id').value.trim(),setAsActive:!$('model').value,completeOnboarding:true};}
function fillProvider(){const p=(state.providers.providers || []).find(p=>p.id===$('provider-id').value);if(!p)return;$('base-url').value=p.baseUrl || '';$('provider-context-window').value=p.contextWindow || 128000;$('api-key').value='';$('api-key').placeholder=p.apiKeyMasked || (p.credentialSource==='environment'?`Using ${p.environmentVariable}`:'Leave blank to check environment');$('provider-env').textContent=p.credentialSource==='environment'?`Credential source: environment · ${p.environmentVariable}. The value is not saved to provider settings.`:`When no key is entered or saved, checks ${(p.environmentCandidates || []).join(', ') || 'no key variable for this provider'}. Restart the app after changing its environment.`;$('model-id').value=p.configured?p.selectedModel || '':'';replace('provider-models',(p.models || []).map(m=>option(m.id,m.label)));$('provider-message').textContent=p.configured?QuixiAnalysis.connectionStatus(p).text:'';$('connection-editor-title').textContent=p.configured?`Edit ${p.name}`:`Add ${p.name}`;}
function showProviders(){replace('provider-id',(state.providers.providers||[]).map(p=>option(p.id,`${p.name}${p.configured?' · configured':''}`)));$('provider-id').value=state.providers.activeProvider || $('provider-id').value;fillProvider();renderConnections();if(!$('provider-dialog').open)$('provider-dialog').showModal();}
// Connections list: saved provider state and real test results only.
async function connectionAction(button,task,label){try{await busy(button,task,label);}catch(e){$('provider-message').textContent=e.message;}}
function editConnection(id){$('provider-id').value=id;fillProvider();$('base-url').focus();}
function renderConnections(){
  const list=(state.providers.providers || []).filter(p=>p.configured);
  replace('connection-list',list.length?list.map(p=>{
    const st=QuixiAnalysis.connectionStatus(p),row=el('div',undefined,'connection-row'),info=el('div');
    info.append(el('strong',p.name),el('span',show(st.detail),'connection-detail'));
    const edit=el('button','Edit','small'),test=el('button','Test','small');edit.type=test.type='button';
    edit.onclick=()=>editConnection(p.id);
    test.onclick=()=>connectionAction(test,async()=>{const r=await providerApi('/test',{providerId:p.id});await refreshState();renderConnections();$('provider-message').textContent=`${p.name}: ${r.ok?'connected':'connection failed'} · ${show(r.message || '')}`;},'Testing…');
    row.append(info,el('span',st.text,`badge${st.ok===true?' completed':st.ok===false?' failed':''}`),edit,test);return row;
  }):[el('p','No connections yet. Add a cloud API or a local OpenAI-compatible endpoint.','muted')]);
}

// REA: live catalog + availability, persistent artifact selection, full result history.
function unwrap(response){if(response?.structuredContent)return response.structuredContent;for(const c of response?.content || [])if(c.type==='text'){try{return JSON.parse(c.text);}catch{}}return response;}
function sessionResult(value){return value?.result || value;}
function renderRuntimeSettings(value){
  const settings=value.settings || value;state.rea.settings=settings;
  for(const [id,key] of [['rea-heap','ghidraHeapMiB'],['rea-startup-timeout','ghidraStartupTimeoutSecs'],['rea-call-timeout','callTimeoutSecs']]){
    if(settings[key]!==undefined && document.activeElement!==$(id))$(id).value=settings[key];
  }
  if(settings.mode && !$('rea-runtime').value)$('rea-runtime').value=settings.mode;
  const runtime=value.runtime || {},bundle=runtime.bundled || {},components=bundle.declaredComponents || bundle,server=runtime.serverInfo || {};
  $('rea-runtime-info').textContent=[server.name?`Connected: ${server.name} ${server.version || ''}`:'No live server identity yet.',
    bundle.rea?`Bundled: REA ${bundle.rea}, Ghidra ${components.ghidra || 'unknown'}, Node ${components.node || 'unknown'}`:'',...(runtime.warnings || []),value.settingsError || ''].filter(Boolean).join('\n');
}
async function loadRuntimeSettings(){renderRuntimeSettings(await pg('rea/settings'));}
async function saveRuntimeSettings(){
  if(running() || state.rea.operation || state.rea.connecting)throw new Error('Finish the active analysis or task before changing runtime settings.');
  const values=[['ghidraHeapMiB','rea-heap',512,65536],['ghidraStartupTimeoutSecs','rea-startup-timeout',60,7200],['callTimeoutSecs','rea-call-timeout',30,14400]],settings={};
  for(const [key,id,min,max] of values){const v=Number($(id).value);if(!Number.isInteger(v) || v<min || v>max)throw new Error(`${$(id).labels[0].textContent} must be a whole number from ${min} to ${max}.`);settings[key]=v;}
  if($('rea-runtime').value)settings.mode=$('rea-runtime').value;
  renderRuntimeSettings(await pg('rea/settings',settings));state.rea.connected=false;state.rea.opened.clear();
  await connectRea();$('rea-runtime-message').textContent='Settings saved. The analysis session restarted; open the target again to continue.';
}
async function connectRea(){
  state.rea.connecting=true;updateAnalysisControls();updateControls();
  $('rea-health').textContent='Starting the selected runtime and checking providers…';$('rea-health').classList.add('busy');
  try{const result=await pg('rea/connect',$('rea-runtime').value?{mode:$('rea-runtime').value}:{});$('rea-runtime').value=result.mode;state.rea.connected=true;state.rea.tools=result.tools || [];state.rea.session=result.session;state.rea.availability.clear();
    if(result.settings || result.runtime)renderRuntimeSettings(result);
    const session=sessionResult(result.session);for(const group of session.tool_availability?.groups || [])for(const name of group.names)state.rea.availability.set(name,group);
    const available=[...state.rea.availability.values()].filter(g=>g.available).length;
    const providers=session.analysis_provider_candidates || [];
    const ghidra=providers.find(p=>(p.id || p.provider_id || p.provider?.id)==='ghidra');
    const version=session.server_identity?.package_version || session.server_identity?.package?.version || session.server_identity?.version || '';
    const openPath=session.path || session.target?.path || session.binary_path;if(typeof openPath==='string' && openPath)state.rea.opened.add(openPath);
    $('rea-health').textContent=`REA ${version} (${result.mode}) connected · ${available} currently available tools / ${state.rea.tools.length} advertised.\n${session.path || session.target?.path || session.binary_path || 'Select an artifact and open it to enable target-specific tools.'}${ghidra?`\nGhidra: ${ghidra.availability?.status || String(ghidra.available ?? 'check tool availability')}`:''}`;
    $('rea-badge').textContent='Connected';$('rea-badge').className='badge completed';$('rea-connect').textContent='Refresh tools';renderTools(undefined,true);await refreshConnectionBadges();
  }catch(e){state.rea.connected=false;$('rea-badge').textContent='Unavailable';$('rea-badge').className='badge failed';$('rea-health').textContent=e.message;throw e;}finally{state.rea.connecting=false;$('rea-health').classList.remove('busy');updateAnalysisControls();updateControls();refreshGuide(true);}
}
function renderTools(preferred,preserve=false){
  const previous=$('rea-tool').value,draft=$('rea-arguments').value;
  const old=preferred || $('rea-tool').value;const query=$('rea-search').value.trim().toLowerCase();
  const tools=state.rea.tools.filter(t=>!query || `${t.name} ${t.description}`.toLowerCase().includes(query));
  tools.sort((a,b)=>Number(!!state.rea.availability.get(b.name)?.available)-Number(!!state.rea.availability.get(a.name)?.available) || a.name.localeCompare(b.name));
  replace('rea-tool',tools.length?tools.map(t=>{const availability=state.rea.availability.get(t.name);const o=option(t.name,`${availability?.available?'●':'○'} ${t.name}`);o.title=availability?.remediation || '';return o;}):[option('','No matching tools')]);
  if(tools.some(t=>t.name===old))$('rea-tool').value=old;else if(tools.some(t=>t.name==='open_binary'))$('rea-tool').value='open_binary';
  toolChanged();
  if(preserve && previous===$('rea-tool').value){$('rea-arguments').value=draft;syncAnalysisInputs();}
}
function toolChanged(){
  const tool=state.rea.tools.find(t=>t.name===$('rea-tool').value);const availability=state.rea.availability.get(tool?.name);
  const description=tool?.description || '', brief=description.match(/^.*?[.!?](?:\s|$)/s)?.[0].trim() || description.split('\n')[0];
  $('rea-tool-summary').textContent=tool?(brief.length>220?brief.slice(0,217)+'…':brief):'Choose a tool to view its arguments and results.';
  $('rea-description').textContent=tool?.description || '';$('rea-schema').textContent=JSON.stringify(tool?.inputSchema || {},null,2);
  $('rea-availability').textContent=availability && !availability.available?`${availability.reason}: ${availability.remediation || 'Unavailable for this target or host.'}`:'';
  const properties=tool?.inputSchema?.properties || {},args=QuixiAnalysis.defaults(tool || {},state.rea.target,$('rea-provider').value);
  $('rea-arguments').value=JSON.stringify(args,null,2);
  const inputs=[];
  for(const key of ['pattern','procedure'])if(properties[key]?.type==='string'){
    const label=el('label',key==='pattern'?'Search text or regular expression':'Function name or address','field-label');label.htmlFor=`rea-input-${key}`;
    const input=el('input');input.id=`rea-input-${key}`;input.dataset.argument=key;input.type='text';input.autocomplete='off';input.spellcheck=false;
    input.placeholder=key==='pattern'?'Enter text to find…':'Choose a function from Functions, or enter its address';
    input.addEventListener('input',()=>{try{const args=JSON.parse($('rea-arguments').value);if(!args || typeof args!=='object' || Array.isArray(args))throw new Error('Correct the JSON arguments first.');args[key]=input.value;$('rea-arguments').value=JSON.stringify(args,null,2);updateAnalysisControls();}catch(e){error(e);}});
    inputs.push(label,input);
  }
  replace('rea-inputs',inputs);syncAnalysisInputs();
}
function syncAnalysisInputs(){
  try{const args=JSON.parse($('rea-arguments').value);for(const input of $('rea-inputs').querySelectorAll('input'))input.value=typeof args?.[input.dataset.argument]==='string'?args[input.dataset.argument]:'';}catch{/* Keep an incomplete JSON draft visible. */}
  updateAnalysisControls();
}
function updateAnalysisControls(){
  const tool=state.rea.tools.find(t=>t.name===$('rea-tool').value),locked=!!state.rea.operation || !!state.rea.connecting || !!running();
  let issues=[];try{if(tool)issues=QuixiAnalysis.issues(tool,JSON.parse($('rea-arguments').value));}catch{issues=['Arguments must be valid JSON.'];}
  $('rea-validation').textContent=issues.join('\n');$('rea-validation').hidden=!issues.length;
  if(issues.length && state.rea.target && !$('view-analysis').hidden && !$('rea-inputs').querySelector('input'))window.QuixiWorkflow?.reveal('rea-arguments',{scroll:false});
  $('rea-run').disabled=locked || !tool || state.rea.availability.get(tool?.name)?.available===false || !!issues.length;
  for(const id of ['rea-connect','rea-close','rea-restart','rea-runtime','rea-provider','rea-runtime-save','rea-heap','rea-startup-timeout','rea-call-timeout','artifact-file','artifact-folder','artifact-set-path','rea-tool','rea-search','rea-arguments','rea-record','history-target','history-tool'])$(id).disabled=locked;
  for(const b of document.querySelectorAll('[data-rea-tool], #rea-inputs input, [data-analysis-action]'))b.disabled=locked;
  const nav=state.rea.nav;$('code-back').disabled=locked || nav.index<1;$('code-forward').disabled=locked || nav.index>=nav.items.length-1;
  $('code-rename').disabled=$('code-comment').disabled=locked || !state.rea.current;
  $('rea-use').disabled=$('rea-export').disabled=!state.rea.record || !!state.rea.record.transient;
  updateSourceControls();refreshGuide();
}
const historySeq=QuixiAnalysis.sequencer(),recordSeq=QuixiAnalysis.sequencer();
async function loadAnalysisHistory(){const t=historySeq.next(),result=await pg('rea/inventory');if(!historySeq.current(t))return;state.rea.target=result.target || '';state.rea.targetIsDirectory=!!result.targetIsDirectory;state.rea.records=result.records || [];
  $('artifact-path').textContent=show(state.rea.target) || 'EXE · DLL · .NET · ASAR · JavaScript · archives';$('artifact-path').title=state.rea.target;$('artifact-name').textContent=show(state.rea.target.split(/[\\/]/).pop()) || 'Select an artifact';
  state.rea.artifactGroups=result.artifactGroups || [];renderArtifactInventory();renderHistory();window.QuixiInvestigations?.updateCandidates();
  renderReconstruction();
  await loadDossiers();
}
function renderArtifactInventory(){
  const groups=state.rea.artifactGroups || [];
  $('artifact-inventory-count').textContent=groups.length;
  replace('artifact-inventory',groups.length?groups.map(g=>{
    const row=el('div',undefined,'artifact-version'),path=g.target || g.path || '',identity=g.artifactIdentity || g.identity || g;
    const b=el('button',show(path.split(/[\\/]/).pop() || path),'link');b.type='button';b.title=path;b.disabled=!!running() || !!state.rea.operation;
    b.onclick=()=>selectArtifact({path}).catch(error);
    row.append(b,el('code',identity.sha256?identity.sha256.slice(0,16):'Identity unverified'),el('span',`${g.recordCount ?? g.records?.length ?? g.count ?? 0} records`,'muted'));
    return row;
  }):[el('p','Saved analyses will be grouped by artifact and content hash.','muted')]);
}
function renderHistory(){
  const records=state.rea.records,{targets,tools}=QuixiAnalysis.historyFacets(records),target=$('history-target').value,tool=$('history-tool').value;
  if(replaceSelect('history-target',[option('','All targets'),...targets.map(t=>{const o=option(t,show(t.split(/[\\/]/).pop() || t));o.title=t;return o;})]))setSelect('history-target',targets.includes(target)?target:'');
  if(replaceSelect('history-tool',[option('','All tools'),...tools.map(t=>option(t,t))]))setSelect('history-tool',tools.includes(tool)?tool:'');
  const shown=QuixiAnalysis.filterHistory(records,{target:$('history-target').value,tool:$('history-tool').value}),old=$('rea-record').value;
  replaceSelect('rea-record',shown.length?shown.map(r=>option(r.id,`${r.failed?'Failed':'Result'} · ${r.provider || 'rea'} · ${r.tool} · ${new Date(r.created).toLocaleString()}`)):[option('',records.length?'No analyses match these filters':'No analyses yet')]);
  if(shown.some(r=>r.id===old))setSelect('rea-record',old);
  if(state.rea.record?.transient)$('rea-record').selectedIndex=-1;
}
function selectRecord(id){
  if(!Array.from($('rea-record').options).some(o=>o.value===id) && state.rea.records.some(r=>r.id===id)){$('history-target').value='';$('history-tool').value='';renderHistory();}
  $('rea-record').value=id;
}
async function showSaved(record,opts){await loadAnalysisHistory();if(!record.transient)selectRecord(record.id);renderEvidence(record,opts);}
function resetNavigation(){state.rea.nav={items:[],index:-1};state.rea.current=null;state.rea.procs=new Map();state.rea.addresses=new Map();}
async function selectArtifact(data){if(running() || state.rea.operation)throw new Error('Finish the active analysis before changing its target.');const result=await pg('rea/select',data);if(result.cancelled)return;decompileSourceId='';$('decompile-input').value='';$('decompile-input-source').textContent='Select original evidence below.';state.rea.record=null;resetNavigation();$('code-toolbar').hidden=true;$('code-note').hidden=true;$('recovered-code').hidden=true;setRaw(null);replace('evidence-summary',[el('p','Artifact selected. Open it for native analysis, then browse Functions or search Strings.','muted')]);state.rea.hint=null;await loadAnalysisHistory();toolChanged();updateAnalysisControls();refreshGuide(true);}
async function runRea(e){e.preventDefault();const tool=$('rea-tool').value;let args;try{args=JSON.parse($('rea-arguments').value);}catch{throw new Error('Arguments must be valid JSON.');}
  await executeAnalysis(tool,args);
}
// persist:false views (inventory pages, search-all) return the same record shape without adding history.
async function reaCall(tool,args,persist=true){const record=await pg('rea/tool',persist?{tool,arguments:args}:{tool,arguments:args,persist:false});if(!persist)record.transient=true;return record;}
async function executeAnalysis(tool,args,browse=true,opts={}){
  if(state.rea.operation || running())throw new Error('Finish the active task or analysis first.');
  const declared=state.rea.tools.find(t=>t.name===tool);if(!declared)throw new Error('Refresh the live REA tool catalog first.');
  const issues=QuixiAnalysis.issues(declared,args);if(issues.length)throw new Error(issues.join('\n'));
  const persist=opts.persist!==false;
  state.rea.operation=true;updateAnalysisControls();updateControls();
  try{return await busy($('rea-run'),async()=>{
    $('rea-health').textContent=`Running ${tool}… Native import and analysis can take several minutes.`;
    let record=await reaCall(tool,args,persist);
    // Track what this REA session has actually opened; opening is not exploration.
    if(tool==='open_binary' && !record.failed)state.rea.opened.add(record.target || args.path || state.rea.target);
    if(tool==='close_binary' && !record.failed)state.rea.opened.clear();
    const view=!record.failed && QuixiAnalysis.nativeView(unwrap(record.response));
    if(browse && view?.kind==='summary' && state.rea.tools.some(t=>t.name==='inspect_analysis_view')){
      // The summary retains the provider's rows; paging does not reanalyse the binary or add history.
      record=await reaCall('inspect_analysis_view',QuixiAnalysis.pageArguments(view,0),false);
    }
    if(persist)await showSaved(record,opts);else renderEvidence(record,opts);
    if(persist && !opts.quiet && tool!=='inspect_analysis_view')await connectRea();
    else $('rea-health').textContent=`${tool} ${record.failed?'reported an error':'completed'}${record.transient?' · view not saved to history':''}.`;
    return record;
  },'Analysing…');}finally{state.rea.operation=false;updateAnalysisControls();updateControls();refreshGuide(true);}
}
// Row and code actions: select the live tool, fill its own schema fields, then run it.
async function reaQuick(name,intents,opts={}){
  if(state.rea.operation || running())throw new Error('Finish the active task or analysis first.');
  if(!state.rea.connected)await connectRea();
  const tool=state.rea.tools.find(t=>t.name===name);if(!tool)throw new Error(`This REA version does not advertise ${name}. Refresh tools or choose another supported tool.`);
  const args={...QuixiAnalysis.defaults(tool,state.rea.target,$('rea-provider').value),...QuixiAnalysis.fillArgs(tool.inputSchema,intents)};
  $('rea-search').value='';renderTools(name);$('rea-arguments').value=JSON.stringify(args,null,2);syncAnalysisInputs();
  return executeAnalysis(name,args,!!opts.browse,{quiet:true,...opts});
}
function decompileAt(procedure,provider='rea',opts={}){return provider==='ida'?idaQuick('decompile',{address:procedure},opts):reaQuick('procedure_pseudo_code',{address:procedure},opts);}
function rememberProcedure(name,address){if(!name || !address)return;state.rea.procs.set(name,address);const key=QuixiAnalysis.address(address,true);if(key)state.rea.addresses.set(key,{address,name});}
function collectValues(value, keys, found=[], depth=0){if(depth>14 || !value || typeof value!=='object')return found;for(const [key,v] of Object.entries(value)){if(keys.has(key))found.push(v);if(typeof v==='object')collectValues(v,keys,found,depth+1);}return found;}
// The complete result is serialised once per record and only pretty-printed when opened and small enough.
let rawRecord=null,rawCompact='',rawShown=false;
function setRaw(record){
  rawRecord=record;rawShown=false;$('rea-output').textContent='';rawCompact=record?JSON.stringify(record):'';
  $('evidence-raw-summary').textContent=record?`Complete result · ${QuixiAnalysis.formatSize(rawCompact.length)}${record.transient?' · not saved to history':''}`:'Complete result';
  showRaw();
}
function showRaw(){
  if(rawShown || !rawRecord || !$('evidence-raw').open)return;rawShown=true;
  const r=QuixiAnalysis.rawText(rawCompact);$('rea-output').textContent=r.text;
  if(r.truncated || !r.pretty)$('evidence-raw-summary').textContent+=r.truncated?' · display truncated; Export JSON keeps the full record':' · compact view for size';
}
function decompiledFunction(record){
  // IDA bridge records are saved as provider "ida-bridge".
  const provider=record.provider==='ida-bridge'?'ida':record.provider || 'rea',args=record.arguments || {};
  if(record.failed || !(provider==='rea' && record.tool==='procedure_pseudo_code' || provider==='ida' && record.tool==='decompile'))return null;
  const procedure=String(args.procedure ?? args.addr ?? (Array.isArray(args.addrs)?args.addrs[0]:args.address) ?? '');if(!procedure)return null;
  const auto=procedure.match(/^(?:FUN|sub)_([0-9a-fA-F]{4,})$/),key=QuixiAnalysis.address(procedure,provider==='ida');
  const address=key?procedure:state.rea.procs.get(procedure) || (auto?QuixiAnalysis.address(auto[1],true):null);
  const name=key?state.rea.addresses.get(key)?.name || procedure:procedure;
  return {provider,procedure,address,name};
}
function noteNavigation(entry,opts){
  const nav=state.rea.nav;if(opts.nav || opts.replaceNav){if(nav.index>=0)nav.items[nav.index]=entry;else{nav.items=[entry];nav.index=0;}return;}
  if(nav.items[nav.index]?.recordId===entry.recordId)return;
  nav.items=nav.items.slice(0,nav.index+1);nav.items.push(entry);if(nav.items.length>100)nav.items.shift();nav.index=nav.items.length-1;
}
async function navigate(step){
  const nav=state.rea.nav,entry=nav.items[nav.index+step];if(!entry || state.rea.operation || running())return;
  nav.index+=step;updateAnalysisControls();
  try{
    if(entry.recordId && !entry.transient){const t=recordSeq.next(),record=await pg('rea/evidence',{id:entry.recordId});if(recordSeq.current(t)){selectRecord(record.id);renderEvidence(record,{nav:true});}}
    else await decompileAt(entry.procedure,entry.provider,{nav:true});
  }catch(e){nav.index-=step;updateAnalysisControls();throw e;}
}
const codeHighlightLimit=300000;
function linkName(name){return state.rea.procs.has(name) || /^(FUN|sub|thunk_FUN)_[0-9a-fA-F]{4,}$/.test(name)?name:null;}
function linkAddress(text){const key=QuixiAnalysis.address(text.replace(/[uUlL]+$/,''));return key && state.rea.addresses.get(key)?.address || null;}
// Tokens become text nodes and spans built with textContent; nothing is parsed as markup.
function renderCode(code){
  const pre=$('recovered-code'),text=show(code,true);pre.hidden=!code;
  if(!code || text.length>codeHighlightLimit){pre.textContent=text;return;}
  pre.replaceChildren(...QuixiAnalysis.cTokens(text).map(t=>{
    const link=t.type==='ident'?linkName(t.text):t.type==='number'?linkAddress(t.text):null;
    if((t.type==='plain' || t.type==='ident') && !link)return document.createTextNode(t.text);
    const span=el('span',t.text,`tok-${t.type}${link?' tok-link':''}`);
    if(link){span.dataset.proc=link;span.tabIndex=0;span.title=`Decompile ${link}`;}
    return span;
  }));
}
function renderEvidence(record,opts={}){
  recordSeq.next();
  state.rea.record=record;const value=unwrap(record.response);$('evidence-raw').open=!!record.failed;setRaw(record);
  const hint=QuixiAnalysis.sameTarget(record.target,state.rea.target)?QuixiAnalysis.kindHint(record.tool,!!record.failed,rawCompact):{};
  if(Object.keys(hint).length)state.rea.hint={...(state.rea.hint || {}),...hint,target:state.rea.target};
  const nodes=[el('h3',`${record.failed?'Analysis reported an error':record.transient?'Analysis view':'Analysis saved'} · ${record.provider || 'rea'} · ${record.tool}`),el('p',show(record.target) || 'Session inspection','muted')];
  const identity=record.artifactIdentity;
  if(identity?.sha256)nodes.push(el('p',`Artifact SHA-256: ${identity.sha256}`,'identity'));
  if(identity?.status && identity.status!=='verified')nodes.push(el('p',`Artifact identity: ${identity.status}. ${identity.reason || 'Review this record before using it as evidence for the current build.'}`,'field-note'));
  if(!identity)nodes.push(el('p','Legacy record: no verified artifact identity is attached. It remains available for review.','field-note'));
  if(record.transient)nodes.push(el('p','This page view is not saved to the analysis history.','field-note'));
  const fn=decompiledFunction(record);
  if(record.provider && record.provider!=='rea'){nodes.push(el('p',`${record.kind} · ${record.created} · record ${record.id}`,'identity'));if(record.provenance?.association)nodes.push(el('p',show(record.provenance.association),'field-note'));for(const limit of record.provenance?.limitations || [])nodes.push(el('p',show(limit),'field-note'));const texts=(record.response?.content || []).filter(c=>c.type==='text').map(c=>c.text).join('\n');if(texts && !fn)nodes.push(el('pre',show(texts,true)));}
  const ids=[...new Set(collectValues(value,new Set(['evidence_id','parent_evidence_id'])).filter(v=>typeof v==='string'))];
  if(ids.length)nodes.push(el('p',show(ids.join('\n'),true),'identity'));
  const limits=collectValues(value,new Set(['limitations','unknowns'])).flat().filter(v=>v!=null && (typeof v!=='string' || v));
  if(limits.length){const details=el('details');details.append(el('summary',`Limitations & unknowns (${limits.length})`));const ul=el('ul',undefined,'limitations');for(const v of limits)ul.append(el('li',show(typeof v==='string'?v:JSON.stringify(v))));details.append(ul);nodes.push(details);}
  const result=value?.result || value;const facts=Object.entries(result || {}).filter(([k,v])=>!['limitations','unknowns','evidence','graph','raw_result','tool_availability','server_identity','normalized_result'].includes(k) && (typeof v==='string' || typeof v==='number' || typeof v==='boolean'));
  for(const [k,v] of facts.slice(0,15))nodes.push(el('p',`${show(k.replaceAll('_',' '))}: ${show(String(v))}`));
  const failure=QuixiReconstruction.failure(record,value);
  if(failure){nodes.push(el('p',failure.message,'analysis-error'),el('p',failure.guidance,'field-note'));
    if(failure.nextTool){const b=el('button','Prepare native analysis','small');b.onclick=()=>prepareReaTool(failure.nextTool).catch(error);nodes.push(b);}}
  const view=!record.failed && QuixiAnalysis.nativeView(value);
  if(view)renderNativeInventory(record,view,nodes);
  else if(value?.normalized_result?.summary){const summary=el('details');summary.append(el('summary','Returned observations'),el('pre',JSON.stringify(value.normalized_result.summary,null,2)));nodes.push(summary);}
  if(!record.failed && !facts.length && !limits.length && !ids.length)nodes.push(el('p','Open Complete result below to inspect the returned observations and metadata.','muted'));
  const codeKeys=['pseudocode','pseudo_code','assembly','decompiled_code',...(/pseudo|assembly/.test(record.tool)?['normalized_result']:[]),...(/^ida/.test(record.provider || '') && /decompil|disasm/.test(record.tool)?['code','decompiled','asm','disasm','text']:[])];
  const code=collectValues(value,new Set(codeKeys)).filter(v=>typeof v==='string' && v.trim()).join('\n\n');
  renderCode(code);
  if(fn && !code)nodes.push(el('p','The provider returned no decompiled code for this function. Review the complete result and limitations.','field-note'));
  state.rea.current=fn;$('code-toolbar').hidden=!fn;
  if(fn){$('code-function').textContent=show(`${fn.provider==='ida'?'IDA':'REA'} · ${fn.name}${fn.address && fn.address!==fn.name?` @ ${fn.address}`:''}`);$('code-function').title=$('code-function').textContent;noteNavigation({...fn,recordId:record.id,transient:!!record.transient},opts);}
  $('code-note').textContent=opts.note || '';$('code-note').hidden=!opts.note;
  replace('evidence-summary',nodes);if(record.transient)$('rea-record').selectedIndex=-1;updateAnalysisControls();
}

function renderNativeInventory(record,view,nodes){
  const functions=/procedures$/.test(view.parent_operation),label=functions?'functions':'strings / names';
  const same=QuixiAnalysis.sameTarget(record.target,state.rea.target);
  const action=(title,handler)=>{const b=el('button',title,'small');b.type='button';b.dataset.analysisAction='';b.onclick=()=>{if(!QuixiAnalysis.sameTarget(record.target,state.rea.target)){error(new Error('Select this evidence record’s artifact before using its live analysis.'));return;}clearError();handler().catch(error);};return b;};
  const page=offset=>executeAnalysis('inspect_analysis_view',QuixiAnalysis.pageArguments(view,offset,view.view?.limit || 50),false,{persist:false});
  if(!same)nodes.push(el('p','This saved result belongs to another artifact. Select that artifact before browsing its live evidence.','field-note'));
  if(view.kind==='summary'){
    nodes.push(el('p',`${view.summary?.row_count ?? 'Unknown number of'} retained ${label}. Discovery coverage remains ${view.summary?.discovery_coverage || 'unknown'}.`));
    nodes.push(action(`Browse ${label}`,()=>page(0)));return;
  }
  const rows=view.rows || [],offset=view.view?.offset || 0,limit=view.view?.limit || 50;
  nodes.push(el('h3',`${functions?'Functions':'Strings / names'} · ${rows.length ? offset+1 : 0}–${offset+rows.length} of ${view.coverage?.total ?? '?'} retained rows`));
  nodes.push(el('p','These are the provider’s observed rows. This count does not prove complete discovery. Use ↑/↓ and Enter in the table.','field-note'));
  const bar=el('div',undefined,'inventory-toolbar'),filter=el('input'),jump=el('input');
  filter.type='search';filter.placeholder='Filter this page…';filter.setAttribute('aria-label',`Filter the loaded ${label}`);filter.dataset.analysisAction='';
  jump.placeholder='Go to address';jump.setAttribute('aria-label','Go to address');jump.autocomplete='off';jump.spellcheck=false;jump.dataset.analysisAction='';
  const searchAll=action('Search all',async()=>{const pattern=filter.value.trim();if(!pattern)throw new Error(`Enter text to search all retained ${label}.`);await reaQuick(functions?'search_procedures':'search_strings',{pattern},{persist:false,browse:true});});
  const go=action('Go',async()=>{const address=QuixiAnalysis.address(jump.value,true);if(!address)throw new Error('Enter a hexadecimal address such as 0x401000.');if(functions)await decompileAt(address);else await reaQuick('xrefs',{address});});
  bar.append(filter,searchAll,jump,go);nodes.push(bar);
  const scroll=el('div',undefined,'inventory-scroll'),table=el('table',undefined,'inventory-table'),head=el('tr');
  for(const title of ['Address',functions?'Function':'Value',functions?'Actions':'Kind · actions'])head.append(el('th',title));
  const thead=el('thead');thead.append(head);table.append(thead);const tbody=el('tbody'),entries=[],withIda=idaConnected();
  for(const row of rows){const r=row.record || {},tr=el('tr'),address=typeof r.address==='string' && r.address.trim()?r.address:null;
    tr.dataset.row='';tr.tabIndex=0;tr.append(el('td',show(r.address || '—')),el('td',show(typeof r.value==='string'?r.value:JSON.stringify(r.value ?? r))));
    const td=el('td'),box=el('div',undefined,'row-actions'),procedure=functions && QuixiAnalysis.procedure(row);
    if(procedure){
      if(typeof r.value==='string')rememberProcedure(r.value,address || procedure);
      box.append(action('Decompile',()=>decompileAt(procedure)),action('Callers',()=>reaQuick('procedure_callers',{address:procedure})),action('Callees',()=>reaQuick('procedure_callees',{address:procedure})));
      if(address)box.append(action('Xrefs',()=>reaQuick('xrefs',{address})));
      if(withIda && address)box.append(action('IDA decompile',()=>decompileAt(address,'ida')),action('IDA xrefs',()=>idaQuick('xrefs_to',{address})),action('IDA callees',()=>idaQuick('callees',{address})));
      td.append(box);
    }else if(!functions && address){
      box.append(action('Xrefs',()=>reaQuick('xrefs',{address})));if(withIda)box.append(action('IDA xrefs',()=>idaQuick('xrefs_to',{address})));
      td.append(el('span',show(r.string?.encoding || 'Observed'),'field-note'),box);
    }else td.textContent=functions?'External import':show(r.string?.encoding || 'Observed');
    tr.append(td);tbody.append(tr);entries.push([row,tr]);
  }
  filter.addEventListener('input',()=>{for(const [row,tr] of entries)tr.hidden=!QuixiAnalysis.rowMatches(row,filter.value);});
  filter.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();searchAll.click();}else if(e.key==='ArrowDown'){e.preventDefault();tbody.querySelector('tr[data-row]:not([hidden])')?.focus();}});
  jump.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();go.click();}});
  tbody.addEventListener('keydown',e=>{
    const tr=e.target.closest('tr[data-row]');if(!tr || e.target!==tr)return;
    if(e.key==='ArrowDown' || e.key==='ArrowUp'){e.preventDefault();let next=tr;do next=e.key==='ArrowDown'?next.nextElementSibling:next.previousElementSibling;while(next?.hidden);if(next)next.focus();else if(e.key==='ArrowUp')filter.focus();}
    else if(e.key==='Enter'){e.preventDefault();tr.querySelector('button:not(:disabled)')?.click();}
  });
  table.append(tbody);scroll.append(table);nodes.push(scroll);
  if(!rows.length)nodes.push(el('p','No matching rows were returned.','muted'));
  const nav=el('div',undefined,'inventory-pagination');
  if(offset>0)nav.append(action('Previous page',()=>page(Math.max(0,offset-limit))));
  if(Number.isInteger(view.coverage?.next_offset) && view.coverage.next_offset>offset)nav.append(action('Next page',()=>page(view.coverage.next_offset)));
  nodes.push(nav);
}

async function prepareReaTool(name){
  if(state.rea.operation || running())throw new Error('Finish the active task or analysis first.');
  if(!state.rea.connected)await connectRea();
  if(!state.rea.tools.some(t=>t.name===name))throw new Error(`This REA version does not advertise ${name}. Refresh tools or choose another supported tool.`);
  $('rea-search').value='';renderTools(name);
  const target=$('rea-inputs').querySelector('input') || ($('rea-run').disabled ? $('rea-arguments') : $('rea-run'));
  if(window.QuixiWorkflow)window.QuixiWorkflow.reveal(target,{focus:true});else target.focus();
  $('rea-health').textContent=`${name} selected. Review the arguments, then click Run analysis. Opening a native target uses Ghidra in the background.`;
}
function reconstructionInput(phase){
  const project=state.projects.find(p=>p.id===state.project);
  return {phase,target:state.rea.target,targetIsDirectory:state.rea.targetIsDirectory,project:project?.path || '',scope:$('reconstruction-scope').value,goal:$('reconstruction-goal').value,
    observations:$('reconstruction-observations').value,plan:QuixiReconstruction.plans(state.runs,state.project,state.rea.target).find(r=>r.id===$('reconstruction-plan').value),dossier:$('reconstruction-dossier').value,
    recordIds:state.rea.records.filter(r=>QuixiAnalysis.sameTarget(r.target,state.rea.target)).map(r=>r.id)};
}
function renderReconstruction(){
  const old=$('reconstruction-plan').value,plans=QuixiReconstruction.plans(state.runs,state.project,state.rea.target);
  if(replaceSelect('reconstruction-plan',plans.length?plans.map(r=>option(r.id,`${new Date(r.created).toLocaleString()} · ${r.model}`)):[option('','No brief yet · prepare analysis first')]) && plans.some(r=>r.id===old))$('reconstruction-plan').value=old;
  const project=state.projects.find(p=>p.id===state.project);
  $('reconstruction-destination').textContent=project?`Destination: ${project.path.replace(/^\\\\\?\\/, '')}. Use a separate project outside the original application.`:'Open a separate destination project with Open project.';
  $('reconstruction-build').disabled=(!plans.length && !$('reconstruction-dossier').value) || !!running();$('reconstruction-analyse').disabled=!!running();$('reconstruction-export').disabled=!!running() || !state.project || !state.rea.target;
  $('oracle-run').disabled=!!running() || !!state.rea.oracleOperation || !$('reconstruction-dossier').value;$('oracle-retry').disabled=!!running() || !!state.rea.oracleOperation || state.rea.oracle?.status!=='failed' || state.rea.oracle?.config!==`${$('reconstruction-dossier').value}/oracle-cases.json`;
  $('reconstruction-dossier').disabled=!!state.rea.oracleOperation;$('oracle-stop').hidden=!state.rea.oracleOperation;
}
async function loadDossiers(){
  const old=$('reconstruction-dossier').value,project=state.project;
  const result=project?await pg('reconstruction-inventory'):{dossiers:[]};if(project!==state.project)return;
  if(replaceSelect('reconstruction-dossier',[option('','New SPEC from selected brief'),...(result.dossiers || []).map(d=>option(d.path,`${new Date(d.created).toLocaleString()} · ${d.hasBrief?'SPEC saved':'draft without brief'}`))]) && result.dossiers?.some(d=>d.path===old))$('reconstruction-dossier').value=old;renderReconstruction();
  refreshOracleInfo().catch(()=>{});
}
// Read-only preview of the selected suite tells the guide whether it declares cases and is approved.
const oracleSeq=QuixiAnalysis.sequencer();
async function refreshOracleInfo(){
  const dossier=$('reconstruction-dossier').value,t=oracleSeq.next();
  if(!dossier || !state.project){state.rea.oracleInfo=null;refreshGuide();return;}
  let info={dossier,cases:null,approved:false};
  try{const p=await pg('oracle-preview',{config:`${dossier}/oracle-cases.json`});info={dossier,cases:Array.isArray(p.cases)?p.cases.length:null,approved:!!p.approved};}catch{/* Unknown until previewed. */}
  if(oracleSeq.current(t)){state.rea.oracleInfo=info;refreshGuide();}
}
async function saveDossier(input){
  const result=await pg('reconstruction-export',{scope:input.scope,goal:input.goal,observations:input.observations,briefId:input.plan?.id});
  const excluded=Array.isArray(result.excludedRecords)?result.excludedRecords.length:result.excludedRecords ?? result.excluded ?? 0;
  $('reconstruction-status').textContent=`Saved SPEC.md, oracle-cases.json and ${result.records} analysis records to ${result.path}.${excluded?` Excluded ${excluded} record(s) with missing or different artifact identity; details are in manifest.json.`:''}`;
  await loadDossiers();$('reconstruction-dossier').value=result.relativePath;renderReconstruction();await loadFiles();await refreshOracleInfo();refreshGuide(true);return result;
}
async function prepareReconstruction(phase){
  if(running())throw new Error('Finish the active task before preparing another.');
  const input=reconstructionInput(phase);if(phase==='retry')input.reportPath=state.rea.oracle?.reportPath;
  QuixiReconstruction.prompt(input);
  if(phase==='build' && !input.dossier){const saved=await saveDossier(input);input.dossier=saved.relativePath;}
  const prompt=QuixiReconstruction.prompt(input);
  if(phase==='plan' && !state.rea.connected)await connectRea();
  $('mode').value=phase==='plan'?'ask':'code';$('mode').dispatchEvent(new Event('change'));$('rea-enabled').checked=phase==='plan';
  $('task').value=prompt;state.run='';renderRuns();showView('overview');$('task').focus();updateControls();refreshGuide(true);
}
// Polling refreshes the open dialog only when detection changed and focus is not inside the list.
let toolchainSignature='';
async function loadToolchain(force=true){
  const result=await pg('toolchain/inventory'),signature=JSON.stringify(result.tools);
  if(force===false && (signature===toolchainSignature || $('toolchain-list').contains(document.activeElement)))return;
  toolchainSignature=signature;
  replace('toolchain-list',result.tools.map(t=>{const row=el('section',undefined,'toolchain-row');row.append(el('strong',`${t.group} · ${t.name}`),el('span',t.connected?'Connected':t.connectionNote || t.status,t.connected?'badge completed':'field-note'),el('p',t.note,'field-note'));
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

const mcpApi=(route,data={})=>api(route,data,'/api/quixi/mcp/');
let mcpState={enabled:false};
async function refreshMcp(){
  mcpState=await mcpApi('status');$('mcp-status').textContent=mcpState.enabled?'Enabled':'Disabled';$('mcp-status').className=`badge ${mcpState.enabled?'completed':''}`;
  $('mcp-active').textContent=mcpState.activeRequests?`${mcpState.activeRequests} active request(s)`:'';
  if(document.activeElement!==$('mcp-port'))$('mcp-port').value=mcpState.port;
  $('mcp-port').disabled=mcpState.enabled;$('mcp-url').textContent=mcpState.url;$('mcp-toggle').textContent=mcpState.enabled?'Disable MCP server':'Enable MCP server';
  $('classic-open').disabled=!mcpState.classicAvailable;
  replace('mcp-events',(mcpState.events || []).length?mcpState.events.map(e=>el('p',`${new Date(e.time).toLocaleTimeString()} · ${e.tool} · ${e.failed?'failed':'completed'} · ${e.durationMs} ms`)):[el('p','No calls yet.')]);
}
on('mcp-settings','click',async()=>{$('mcp-dialog').showModal();await refreshMcp();});
on('mcp-close','click',()=>$('mcp-dialog').close());
on('mcp-dialog','close',()=>{$('mcp-config-output').hidden=true;$('mcp-config-output').textContent='';});
on('mcp-toggle','click',async()=>{await busy($('mcp-toggle'),async()=>{await mcpApi(mcpState.enabled?'disable':'enable',{port:Number($('mcp-port').value)});});await refreshMcp();});
on('mcp-config','click',async()=>{const config=await mcpApi('config');if(!$('mcp-dialog').open)return;$('mcp-config-output').textContent=JSON.stringify(config,null,2);$('mcp-config-output').hidden=false;$('mcp-message').textContent='Use this Streamable HTTP configuration in your local MCP client. It contains your access token.';});
on('mcp-rotate','click',async()=>{await mcpApi('rotate');$('mcp-config-output').hidden=true;$('mcp-config-output').textContent='';$('mcp-message').textContent='Access token reset. Re-enable the server and update your client connection config.';await refreshMcp();});
on('classic-configure','click',async()=>{await mcpApi('classic-configure');await refreshMcp();});
on('classic-open','click',()=>busy($('classic-open'),async()=>{await mcpApi('classic-open');$('mcp-message').textContent='Classic opened in a separate window.';},'Opening…'));

let decompileSourceId='';
// Decompile helper: an optional LLM4Decompile tool the Agent model (or the user) calls. Its state comes from decompile/status only.
const helper={status:null,diagram:''};
const helperConnections=()=>(state.providers.providers || []).filter(p=>p.configured && p.apiFormat==='openai' && p.authMode!=='oauth');
function renderHelper(){
  const st=QuixiAnalysis.helperStatus(helper.status,state.providers.providers || []);
  $('helper-status').textContent=st.text;$('helper-status').dataset.state=st.state;$('helper-setup').textContent=st.state==='off'?'Set up':'Change';
  const badge=st.state==='ready'?'Connected · last request succeeded':st.state==='on'?'On · not checked yet':st.state==='off'?'Off':st.state==='unknown'?'Checking…':'Needs setup';
  for(const id of ['decompile-connection','helper-dialog-status']){$(id).textContent=badge;$(id).className=`badge${st.state==='ready'?' completed':/^needs/.test(st.state)?' failed':''}`;}
  $('decompile-summary').textContent=st.text;renderModelsDiagram();refreshGuide();
}
// Connections → Agent model → tools, from live state; rebuilt only when it changes.
function renderModelsDiagram(){
  const connections=(state.providers.providers || []).filter(p=>p.configured).map(p=>p.name),agent=$('model').selectedOptions[0]?.dataset.model || '';
  const st=QuixiAnalysis.helperStatus(helper.status,state.providers.providers || []),signature=JSON.stringify([connections,agent,st]);
  if(helper.diagram===signature)return;helper.diagram=signature;
  const node=(title,detail,cls='')=>{const n=el('div',undefined,`flow-node${cls?` ${cls}`:''}`);n.append(el('strong',title),el('span',detail));return n;};
  const tools=el('div',undefined,'flow-tools');
  tools.append(node('REA / Ghidra','static analysis'),node('IDA bridge','your IDA Pro'),node('x64dbg','debugger'),node('Decompile helper',st.text,`flow-helper ${st.state}`));
  replace('models-diagram',[node('Connections',connections.length?connections.join(' · '):'None yet · add one'),el('div','↓ supply models','flow-arrow'),
    node('Agent model',agent?`${agent} · runs every task`:'Not chosen yet','flow-agent'),el('div','↓ calls tools when needed','flow-arrow'),tools]);
}
async function loadDecompileSettings(){helper.status=await pg('decompile/status');renderHelper();}
function helperProfileNote(){
  const model=$('decompile-model').value.trim(),detected=QuixiAnalysis.helperProfile(model),explicit=$('decompile-profile').value,profile=explicit || detected.profile;
  const label=profile==='llm4-end'?'assembly (End)':'Ghidra/Hex-Rays pseudocode (Ref)';
  $('decompile-profile-note').textContent=!model?'Pick a model to see which function text it takes.':explicit?`Input: ${label} · set under Advanced.`:
    `Input: ${label} · ${detected.reason==='default'?'no Ref/End marker in the model name, so Ref is assumed':`detected because ${detected.reason}`}. Override under Advanced.`;
}
function fillHelperForm(){
  const s=helper.status?.settings || {},conns=helperConnections();
  replace('decompile-provider',conns.length?conns.map(p=>option(p.id,p.name)):[option('','No OpenAI-compatible connection yet')]);
  $('decompile-provider').value=conns.some(p=>p.id===s.provider)?s.provider:conns[0]?.id || '';$('decompile-provider-note').hidden=!!conns.length;
  $('decompile-model').value=s.model || '';$('decompile-profile').value=!s.model || QuixiAnalysis.helperProfile(s.model).profile===s.profile?'':s.profile || '';
  $('decompile-max-tokens').value=String(s.maxTokens || 1024);helperProfileNote();
}
// The saved profile is explicit only when it differs from the one detected for the model.
function decompileSettings(enabled){const model=$('decompile-model').value.trim();return{enabled,provider:$('decompile-provider').value,model,profile:$('decompile-profile').value || QuixiAnalysis.helperProfile(model).profile,maxTokens:Number($('decompile-max-tokens').value)};}
async function helperAction(button,task,label){$('helper-message').classList.remove('analysis-error');try{await busy(button,task,label);}catch(e){$('helper-message').textContent=e.message;$('helper-message').classList.add('analysis-error');}}
async function openHelperSetup(){await loadDecompileSettings();fillHelperForm();$('helper-message').textContent='';if(!$('helper-dialog').open)$('helper-dialog').showModal();}
on('helper-setup','click',openHelperSetup);on('decompile-setup','click',openHelperSetup);on('helper-close','click',()=>$('helper-dialog').close());
on('helper-connections','click',()=>{$('helper-dialog').close();showProviders();});
on('decompile-save','click',()=>helperAction($('decompile-save'),async()=>{
  const settings=decompileSettings(true);
  if(!settings.provider)throw new Error('Choose a connection first. Add an OpenAI-compatible one in Connections.');
  if(!settings.model)throw new Error('Pick a model first. Discover models lists what the connection serves.');
  helper.status=await pg('decompile/configure',{settings});renderHelper();fillHelperForm();
  $('helper-message').textContent=`Enabled · ${settings.model}. The Agent model can call it as a tool; Run helper on this function calls it directly.`;
},'Saving…'));
on('decompile-disable','click',()=>helperAction($('decompile-disable'),async()=>{
  const saved=helper.status?.settings;if(!saved)throw new Error('The helper settings have not loaded yet.');
  helper.status=await pg('decompile/configure',{settings:{...saved,enabled:false}});renderHelper();$('helper-message').textContent='Turned off. Its connection and model are kept for later.';
},'Saving…'));
on('decompile-models','click',()=>helperAction($('decompile-models'),async()=>{
  const provider=$('decompile-provider').value;if(!provider)throw new Error('Choose a connection first.');
  const result=await pg('decompile/models',{provider});
  replace('decompile-model-options',[...result.llm4decompile,...result.models.filter(m=>!result.llm4decompile.includes(m))].map(m=>option(m,m)));
  if(!$('decompile-model').value && result.llm4decompile.length)$('decompile-model').value=result.llm4decompile[0];
  helperProfileNote();await refreshState();
  $('helper-message').textContent=`${result.models.length} models advertised. ${result.llm4decompile.length?`LLM4Decompile: ${result.llm4decompile.join(', ')}`:'No LLM4Decompile model advertised. Serve one on this connection, or type its exact model ID.'} A completion verifies that it can run.`;
},'Discovering…'));
on('decompile-provider','change',()=>{replace('decompile-model-options',[]);$('decompile-model').value='';helperProfileNote();$('helper-message').textContent='Discover models on this connection, or type its exact model ID.';});
on('decompile-model','input',helperProfileNote);on('decompile-profile','change',helperProfileNote);
on('decompile-input-load','click',async()=>{
  const record=state.rea.record,issue=QuixiAnalysis.helperInputIssue(record,helper.status?.settings?.profile || 'llm4-ref');if(issue)throw new Error(issue);
  const result=await pg('decompile/input',{recordId:record.id});$('decompile-input').value=result.input;
  decompileSourceId=record.id;$('decompile-input-source').textContent=`Source record: ${record.id} · ${record.provider || 'rea'} / ${record.tool}${result.note?` · ${result.note}`:''}`;
});
// Only successful original function evidence may become the provenance of a helper request.
const decompileSource=()=>decompileSourceId || (QuixiAnalysis.functionRecord(state.rea.record)?state.rea.record.id:'');
const helperReady=()=>{if(!helper.status?.settings?.enabled)throw new Error('Set up and enable the Decompile helper first (Models → Decompile helper → Set up).');};
on('decompile-input','input',()=>{if(!decompileSourceId && QuixiAnalysis.functionRecord(state.rea.record)){decompileSourceId=state.rea.record.id;$('decompile-input-source').textContent=`Reviewed function linked to source record: ${decompileSourceId}`;}});
on('decompile-run','click',async()=>{
  if(state.rea.operation || running())throw new Error('Finish the active task or analysis first.');
  const id=decompileSource();if(!id)throw new Error('Select a successful original function record (decompiled pseudocode or assembly) first.');
  helperReady();
  state.rea.operation=true;updateAnalysisControls();updateControls();
  try{await busy($('decompile-run'),async()=>{
    const record=await pg('decompile/assist',{recordId:id,input:$('decompile-input').value});
    await showSaved(record);
    await refreshConnectionBadges();$('decompile-message').textContent=record.failed?'The helper request failed. Inspect the saved result.':'Suggestion saved with its source record. Compilation and behaviour remain unverified.';
  },'Running helper…');}finally{state.rea.operation=false;updateAnalysisControls();updateControls();}
});
// The Agent model is the driver: this prepares an Ask task for it that calls the helper as a tool.
on('decompile-prepare','click',async()=>{
  const id=decompileSource();if(!id)throw new Error('Select a successful original function record (decompiled pseudocode or assembly) first.');
  helperReady();const s=helper.status.settings,agent=$('model').selectedOptions[0];
  if(!agent?.dataset.model)throw new Error('Choose the Agent model in the Models card first.');
  if(agent.dataset.provider===s.provider && agent.dataset.model===s.model)throw new Error('The Agent model is set to the Decompile helper model. Choose a general Agent model that can call tools; the helper stays a tool.');
  $('rea-enabled').checked=true;$('mode').value='ask';$('mode').dispatchEvent(new Event('change'));
  $('task').value=`Read original analysis record ${id}. Use the Decompile helper (LLM4Decompile) through decompile_assist to refine the function, then inspect its returned record. Compare its suggestion against the original evidence, explain any uncertainty, and propose concrete compilation and behavioural checks. Do not claim the suggestion is verified or original source.`;
  showView('overview');$('task').focus();
});

// Installed sources share the same artifact and durable evidence history.
const analysisSources = {items:[], debugger:{connected:false,tools:[]}};
async function refreshConnectionBadges(){
  const [sources,status]=await Promise.all([pg('toolchain/sources'),pg('decompile/status')]);helper.status=status;
  const connected=sources.sources.filter(s=>s.connected);
  const badges=connected.map(s=>el('span',`${s.name} · Connected`,'badge completed'));
  if(status.connected)badges.push(el('span',`Decompile helper · ${status.lastSuccess.model} · Connected`,'badge completed'));
  replace('analysis-connections',badges.length?badges:[el('span','No verified live connections','field-note')]);
  renderHelper();
  if($('toolchain-dialog').open)await loadToolchain(false);
}
async function refreshAnalysisSources(){
  const result=await pg('toolchain/sources');analysisSources.items=result.sources || [];
  const old=$('analysis-source').value;
  if(replaceSelect('analysis-source',analysisSources.items.length?analysisSources.items.map(s=>option(s.id,`${s.name} · ${s.integration}`)):[option('','No installed sources · open Toolchain')]) && analysisSources.items.some(s=>s.id===old))$('analysis-source').value=old;
  await selectAnalysisSource(false);await refreshConnectionBadges();await refreshIda().catch(error);
}
async function selectAnalysisSource(prepare=true){
  const source=analysisSources.items.find(s=>s.id===$('analysis-source').value);
  const native=source && ['rea','ghidra','ida','jadx-mcp'].includes(source.id);
  $('rea-source-controls').hidden=!native;$('rea-form').hidden=!native;$('rea-connect').hidden=!native;
  document.querySelector('.analysis-grid').classList.toggle('external-source',!native);
  $('external-analysis').hidden=!!native || !source;$('debugger-panel').hidden=source?.id!=='x64dbg';
  $('source-open').hidden=source?.kind!=='gui';
  $('analysis-source-note').textContent=source?`${source.note} ${source.integration==='Import exported results'?'Use the tool, export the relevant observations, then import them below.':''}`:'Configure installed tools in Toolchain, then refresh.';
  if(native && source.id!=='rea'){
    if(['ghidra','ida'].includes(source.id))$('rea-provider').value=source.id;
    if(prepare){await connectRea();await prepareReaTool(source.id==='jadx-mcp'?'inspect_android_package':'open_binary');}
  }
  if(source?.id==='x64dbg')await refreshDebugger();
  updateSourceControls();
}
function updateSourceControls(){
  const locked=!!state.rea.operation || !!state.rea.connecting || !!running();
  for(const id of ['analysis-source','analysis-sources-refresh','source-open','source-import','source-docs','debugger-toggle','debugger-setup','debugger-cmdline','decompile-save','decompile-disable','decompile-models','decompile-input-load','decompile-run','decompile-prepare','decompile-provider','decompile-model','decompile-profile','decompile-max-tokens','decompile-input'])$(id).disabled=locked;
  for(const id of ['debugger-start','debugger-sessions','debugger-session-pid','debugger-attach','debugger-tool','debugger-arguments','debugger-run'])$(id).disabled=locked || !analysisSources.debugger.connected;
  for(const b of document.querySelectorAll('[data-debugger-tool]'))b.disabled=locked || !analysisSources.debugger.connected;
  if(analysisSources.debugger.sessionConnected){$('debugger-start').disabled=true;$('debugger-attach').disabled=true;}
  const s=ida.status,off=locked || ida.unsupported,tool=s?.tools?.find(t=>t.name===$('ida-tool').value);
  for(const id of ['ida-enable-headless','ida-enable-attached','ida-url','ida-annotations','ida-register-rea','ida-restore-rea'])$(id).disabled=off;$('ida-setup').disabled=locked;
  $('ida-disable').disabled=off || !s?.enabled;$('ida-open').disabled=off || !s?.connected || !state.rea.target;$('ida-close').disabled=off || !s?.session;
  $('ida-tool').disabled=$('ida-arguments').disabled=off || !s?.connected;
  $('ida-run').disabled=off || !s?.connected || !tool || tool.kind==='blocked' || (tool.kind==='annotate' && !s.allowAnnotations);
}
async function refreshDebugger(){
  analysisSources.debugger=await pg('debugger/status');
  const status=analysisSources.debugger,previous=$('debugger-tool').value,draft=$('debugger-arguments').value;
  $('debugger-status').textContent=status.connected?(status.sessionConnected?'Session connected':'Bridge connected · select a session'):'Disabled';
  $('debugger-status').className=`badge ${status.connected?'completed':''}`;
  $('debugger-toggle').textContent=status.connected?'Disable connection':'Enable connection';
  replace('debugger-tool',status.tools.length?status.tools.map(t=>option(t.name,t.name)):[option('','Enable connection first')]);
  $('debugger-tool').value=status.tools.some(t=>t.name===previous)?previous:status.tools.some(t=>t.name==='get_debugger_status')?'get_debugger_status':$('debugger-tool').value;
  debuggerToolChanged();if(previous && previous===$('debugger-tool').value)$('debugger-arguments').value=draft;
  updateSourceControls();
}
function debuggerToolChanged(){
  const tool=analysisSources.debugger.tools.find(t=>t.name===$('debugger-tool').value);
  $('debugger-description').textContent=tool?.description || '';$('debugger-schema').textContent=JSON.stringify(tool?.inputSchema || {},null,2);
  const args={},props=tool?.inputSchema?.properties || {};
  for(const [key,p] of Object.entries(props))if(p.default!==undefined && p.default!==null)args[key]=p.default;
  for(const key of tool?.inputSchema?.required || [])if(!(key in args))args[key]=props[key]?.type==='string'?'':null;
  if('address' in props && ['read_memory','disassemble'].includes(tool?.name))args.address='cip';
  if(tool?.name==='get_memory_map' && 'as_json' in props)args.as_json=true;
  $('debugger-arguments').value=JSON.stringify(args,null,2);
}
async function debuggerAction(route,args,save=true){
  if(state.rea.operation || running())throw new Error('Finish the active task or analysis first.');
  state.rea.operation=true;updateAnalysisControls();updateControls();clearError();
  try{
    const result=await pg(`debugger/${route}`,args);
    if(save)await showSaved(result);
    else if(route==='sessions'){$('debugger-session-output').hidden=false;$('debugger-session-output').textContent=show((result.content || []).filter(c=>c.type==='text').map(c=>c.text).join('\n'),true);}
    return result;
  }finally{
    // Each cleanup step runs even if another fails, and the lock is always released.
    state.rea.operation=false;
    try{await refreshDebugger();}catch(e){error(e);}
    try{await refreshConnectionBadges();}catch(e){error(e);}
    updateAnalysisControls();updateControls();refreshGuide(true);
  }
}
async function runDebugger(e){
  e.preventDefault();const tool=analysisSources.debugger.tools.find(t=>t.name===$('debugger-tool').value);
  if(!tool)throw new Error('Enable the debugger connection first.');
  let args;try{args=JSON.parse($('debugger-arguments').value);}catch{throw new Error('Debugger arguments must be valid JSON.');}
  const issues=QuixiAnalysis.issues(tool,args);if(issues.length)throw new Error(issues.join('\n'));
  await debuggerAction('call',{tool:tool.name,arguments:args});
}
on('analysis-source','change',async()=>{try{await selectAnalysisSource();if(!$('external-analysis').hidden)window.QuixiWorkflow?.reveal('external-analysis',{focus:true});}finally{refreshGuide(true);}});
on('analysis-sources-refresh','click',refreshAnalysisSources);
on('source-open','click',()=>pg('toolchain/open',{id:$('analysis-source').value}));
on('source-docs','click',()=>pg('toolchain/docs',{id:$('analysis-source').value}));
on('source-import','click',async()=>{const result=await pg('toolchain/import-report',{id:$('analysis-source').value});if(!result.cancelled)await showSaved(result);});
on('debugger-toggle','click',()=>debuggerAction(analysisSources.debugger.connected?'disable':'enable',{},false));
on('debugger-start','click',()=>debuggerAction('start',{cmdline:$('debugger-cmdline').value}));
on('debugger-sessions','click',()=>debuggerAction('sessions',{},false));
on('debugger-attach','click',()=>debuggerAction('attach',{sessionPid:Number($('debugger-session-pid').value)}));
on('debugger-tool','change',debuggerToolChanged);
on('debugger-form','submit',runDebugger);
for(const b of document.querySelectorAll('[data-debugger-tool]'))b.onclick=()=>{
  if(!analysisSources.debugger.tools.some(t=>t.name===b.dataset.debuggerTool)){error(new Error('This tool is not advertised by the connected debugger.'));return;}
  $('debugger-tool').value=b.dataset.debuggerTool;debuggerToolChanged();if(window.QuixiWorkflow)window.QuixiWorkflow.reveal('debugger-arguments',{focus:true});else $('debugger-arguments').focus();
};
// IDA Pro bridge: live status, live tool schemas, saved records shaped like debugger records.
const ida={status:null,unsupported:false,shown:'',schemas:new Map(),seq:QuixiAnalysis.sequencer(),statusSeq:QuixiAnalysis.sequencer()};
const idaApi=(route,data={})=>api(`ida/${route}`,data);
function idaConnected(){return !!(ida.status?.connected && ida.status.session);}
async function refreshIda(){
  if(ida.unsupported)return;
  const t=ida.statusSeq.next();let status;
  try{status=await idaApi('status');}catch(e){if(!unsupported(e))throw e;ida.unsupported=true;ida.status=null;renderIda();return;}
  if(!ida.statusSeq.current(t))return;
  if(JSON.stringify(status.tools)!==JSON.stringify(ida.status?.tools))ida.schemas.clear();
  ida.status=status;renderIda();
}
function renderIda(){
  const s=ida.status;
  if(ida.unsupported){$('ida-status').textContent='Unavailable';$('ida-status').className='badge';$('ida-session').textContent='This REA Studio build does not include the IDA Pro bridge.';updateSourceControls();return;}
  if(!s){updateSourceControls();return;}
  const live=idaConnected(),session=s.session;
  $('ida-status').textContent=live?'Connected':s.connected?'Bridge connected · no database':s.enabled?'Enabled · not connected':s.installed===false?'IDA not detected':'Disabled';
  $('ida-status').className=`badge${live?' completed':s.lastError?' failed':''}`;
  $('ida-session').textContent=[`Transport: ${s.transport || 'none'}`,session?`Database: ${show(session.target || 'unknown target')}${session.idbPath?` · ${show(session.idbPath)}`:''}${session.sha256?` · SHA-256 ${show(session.sha256)}`:''}`:'No database open.',
    s.registrationPath?`REA IDA registration: ${show(s.registrationPath)}${s.reaUsesHeadless?' · uses headless IDA':''}`:'REA IDA registration: not configured',
    s.registrationError?`Registration problem: ${show(s.registrationError)}`:''].filter(Boolean).join('\n');
  $('ida-setup').className=s.installed?'small':'primary small';$('ida-setup').textContent=s.installed?'Reinstall IDA bridge…':'Prepare IDA bridge setup';
  if(s.transport==='attached' && s.url && document.activeElement!==$('ida-url'))$('ida-url').value=s.url;
  if(s.lastError)$('ida-message').textContent=show(s.lastError);
  if(document.activeElement!==$('ida-annotations'))$('ida-annotations').checked=!!s.allowAnnotations;
  const tools=s.tools || [],previous=$('ida-tool').value;
  replaceSelect('ida-tool',tools.length?tools.map(t=>{const o=option(t.name,`${t.kind==='blocked'?'⊘':t.kind==='annotate'?'✎':'●'} ${t.name}${t.kind==='blocked'?' · blocked':t.kind==='annotate'?' · writes IDB':''}`);o.disabled=t.kind==='blocked' || t.enabled===false || (t.kind==='annotate' && !s.allowAnnotations);o.title=t.description || '';return o;}):[option('',s.connected?'No tools advertised':'Enable the bridge first')]);
  if(tools.some(t=>t.name===previous))setSelect('ida-tool',previous);
  if($('ida-tool').value!==ida.shown)idaToolChanged().catch(error);else idaToolNotes();
  updateSourceControls();
}
function idaToolNotes(){
  const s=ida.status,tool=s?.tools?.find(t=>t.name===$('ida-tool').value),notes=[];
  $('ida-description').textContent=show(tool?.description || '');
  if(tool?.kind==='annotate' && !s.allowAnnotations)notes.push(`${tool.name} writes to the IDB. Enable Allow annotations to run it.`);
  for(const t of s?.tools || [])if(t.kind==='blocked')notes.push(`Blocked · ${t.name}: ${show(t.description || 'not permitted from REA Studio')}`);
  $('ida-blocked').textContent=notes.join('\n');$('ida-blocked').hidden=!notes.length;
}
async function idaSchema(name){
  if(ida.schemas.has(name))return ida.schemas.get(name);
  const result=await idaApi('tools',{tool:name}),list=Array.isArray(result)?result:Array.isArray(result.tools)?result.tools:[result.tool || result];
  for(const t of list)if(t?.name)ida.schemas.set(t.name,t.inputSchema || t.input_schema || t.schema || {});
  if(!ida.schemas.has(name))ida.schemas.set(name,list.length===1?list[0]?.inputSchema || list[0]?.input_schema || {}:{});
  return ida.schemas.get(name);
}
function idaShowTool(name,schema,args){
  ida.seq.next();ida.shown=name;$('ida-tool').value=name;$('ida-schema').textContent=JSON.stringify(schema,null,2);
  $('ida-arguments').value=JSON.stringify(args || QuixiAnalysis.defaults({name,inputSchema:schema},'',''),null,2);idaToolNotes();updateSourceControls();
}
async function idaToolChanged(){
  const name=$('ida-tool').value;ida.shown=name;idaToolNotes();
  if(!name || !ida.status?.connected){$('ida-schema').textContent='';$('ida-arguments').value='{}';return;}
  const t=ida.seq.next(),schema=await idaSchema(name);if(!ida.seq.current(t) || $('ida-tool').value!==name)return;
  idaShowTool(name,schema);
}
async function idaAction(route,data={},save=false,opts={}){
  if(state.rea.operation || running())throw new Error('Finish the active task or analysis first.');
  state.rea.operation=true;updateAnalysisControls();updateControls();clearError();
  try{const result=await idaApi(route,data);if(save)await showSaved(result,opts);return result;}
  catch(e){if(unsupported(e))throw new Error('This REA Studio build does not include the IDA Pro bridge routes yet.');throw e;}
  finally{
    state.rea.operation=false;
    try{await refreshIda();}catch(e){error(e);}
    try{await refreshConnectionBadges();}catch(e){error(e);}
    updateAnalysisControls();updateControls();refreshGuide(true);
  }
}
// Fill a live IDA schema from intents; anything that does not validate is left in the panel for review.
async function idaQuick(name,intents,opts={}){
  const tool=ida.status?.tools?.find(t=>t.name===name);
  if(!idaConnected() || !tool)throw new Error(tool?'Connect the IDA bridge and open a database first.':`The IDA bridge does not advertise ${name}.`);
  if(tool.kind==='blocked')throw new Error(`${name} is blocked: ${tool.description || 'not permitted from REA Studio'}`);
  if(tool.kind==='annotate' && !ida.status.allowAnnotations)throw new Error('Enable Allow annotations in the IDA Pro panel first.');
  const schema=await idaSchema(name),args=QuixiAnalysis.fillArgs(schema,intents);idaShowTool(name,schema,args);
  const issues=QuixiAnalysis.issues({inputSchema:schema},args);
  if(issues.length || !Object.keys(args).length){$('ida-panel').open=true;window.QuixiWorkflow?.reveal('ida-arguments',{focus:true});throw new Error(`Review the ${name} arguments in the IDA Pro panel, then run it there.\n${issues.join('\n') || 'No matching field was found in its live schema.'}`);}
  return idaAction('call',{tool:name,arguments:args},true,opts);
}
async function runIda(e){
  e.preventDefault();const name=$('ida-tool').value,tool=ida.status?.tools?.find(t=>t.name===name);
  if(!tool || tool.kind==='blocked')throw new Error('Choose an available IDA tool first.');
  if(tool.kind==='annotate' && !ida.status.allowAnnotations)throw new Error('Enable Allow annotations to run tools that write to the IDB.');
  let args;try{args=JSON.parse($('ida-arguments').value);}catch{throw new Error('IDA arguments must be valid JSON.');}
  const issues=QuixiAnalysis.issues({inputSchema:ida.schemas.get(name) || {}},args);if(issues.length)throw new Error(issues.join('\n'));
  await idaAction('call',{tool:name,arguments:args},true);
}
on('ida-enable-headless','click',()=>idaAction('enable',{transport:'headless'}));
on('ida-enable-attached','click',()=>{const url=$('ida-url').value.trim();if(!/^https?:\/\/[^\s/]+/i.test(url))throw new Error('Enter the attached IDA MCP URL, for example http://127.0.0.1:13337/mcp.');return idaAction('enable',{transport:'attached',url});});
on('ida-disable','click',()=>idaAction('disable'));
on('ida-open','click',()=>idaAction('open'));on('ida-close','click',()=>idaAction('close'));
on('ida-annotations','change',async()=>{const allow=$('ida-annotations').checked;try{await idaAction('settings',{allowAnnotations:allow});}catch(e){$('ida-annotations').checked=!allow;throw e;}});
on('ida-tool','change',idaToolChanged);on('ida-form','submit',runIda);
on('ida-register-rea','click',async()=>{await idaAction('register-rea');$('ida-message').textContent='REA is now registered to use headless IDA. Reconnect REA (Connect REA / Refresh tools) to apply it.';});
on('ida-restore-rea','click',async()=>{await idaAction('restore-rea-attached');$('ida-message').textContent='The attached IDA registration was restored. Reconnect REA (Connect REA / Refresh tools) to apply it.';});
on('ida-panel','toggle',()=>{if($('ida-panel').open)return refreshIda();});
// Rename or comment the current function: IDA writes the IDB when annotations are allowed, otherwise REA keeps a session annotation.
async function annotate(kind){
  const current=state.rea.current;if(!current)throw new Error('Decompile a function first.');
  const rename=kind==='rename',where=current.address || current.procedure;
  const value=await askText(rename?'Rename function':'Add comment',rename?'New function name':`Comment at ${show(where)}`,rename?current.name:'');if(!value)return;
  const viaIda=idaConnected() && !!ida.status.allowAnnotations;
  if(!viaIda && !current.address)throw new Error('This function’s address is unknown. Open it from Functions or Go to address, then try again.');
  const intents=rename?{address:where,name:value}:{address:where,comment:value};
  const record=viaIda?await idaQuick(rename?'rename':'set_comments',intents):await reaQuick(rename?'set_address_name':'set_comment',intents);
  if(record?.failed)return;
  if(rename)rememberProcedure(value,where);
  const note=viaIda?`${rename?'Renamed':'Comment added'} by IDA Pro · written to the IDB${ida.status?.session?.idbPath?` (${ida.status.session.idbPath})`:''}.`:`${rename?'Renamed':'Comment added'} by REA · session annotation in the analysis provider; the original binary is unchanged.`;
  await decompileAt(where,current.provider,{replaceNav:true,note:show(note)});
}
on('code-rename','click',()=>annotate('rename'));on('code-comment','click',()=>annotate('comment'));
on('code-back','click',()=>navigate(-1));on('code-forward','click',()=>navigate(1));
const procedureLink=e=>e.target.closest?.('[data-proc]');
on('recovered-code','click',e=>{const link=procedureLink(e);if(link)return decompileAt(link.dataset.proc,state.rea.current?.provider || 'rea');});
on('recovered-code','keydown',e=>{const link=procedureLink(e);if(link && e.key==='Enter'){e.preventDefault();return decompileAt(link.dataset.proc,state.rea.current?.provider || 'rea');}});
on('evidence-raw','toggle',showRaw);
on('history-target','change',renderHistory);on('history-tool','change',renderHistory);
on('ida-setup','click',async()=>{const result=await pg('toolchain/bridge-install-command',{id:'ida-headless'});showView('overview');showConsole('terminal');$('terminal-command').value=result.command;});
// Guided workflow: stages and next steps are computed by QuixiAnalysis from a snapshot of real state only.
const storage=(read,fallback)=>{try{return read();}catch{return fallback;}};
const guide={on:storage(()=>localStorage.getItem('quixi.guide')!=='off',true),top:'',signature:'',preflight:{}};
const failureCache=new WeakMap();
const guideTarget=()=>String(state.rea.target || '').replace(/^\\\\\?\\/,'').replaceAll('\\','/').toLowerCase();
function dismissedSteps(){const all=storage(()=>JSON.parse(localStorage.getItem('quixi.guide.dismissed') || '{}'),{});return Array.isArray(all?.[guideTarget()])?all[guideTarget()]:[];}
function dismissStep(id){
  storage(()=>{const all=JSON.parse(localStorage.getItem('quixi.guide.dismissed') || '{}'),key=guideTarget();all[key]=[...new Set([...(all[key] || []),id])];localStorage.setItem('quixi.guide.dismissed',JSON.stringify(all));});
  if($('re-prompt').dataset.step===id)$('re-prompt').hidden=true;refreshGuide();
}
function lastFailure(record){if(!failureCache.has(record))failureCache.set(record,QuixiAnalysis.failureInfo(record,unwrap(record.response)));return failureCache.get(record);}
function guideSnapshot(){
  const target=state.rea.target,source=analysisSources.items.find(s=>s.id===$('analysis-source').value),s=ida.status || {},record=state.rea.record;
  const hint=state.rea.hint && QuixiAnalysis.sameTarget(state.rea.hint.target,target)?state.rea.hint:{};
  const dossier=$('reconstruction-dossier').value,info=state.rea.oracleInfo?.dossier===dossier?state.rea.oracleInfo:null;
  const oracle=dossier && state.rea.oracle?.config===`${dossier}/oracle-cases.json`?state.rea.oracle:null;
  const helperSettings=helper.status?.settings || {};
  return {project:!!state.project,model:!!$('model').value,connections:(state.providers.providers || []).filter(p=>p.configured).length,
    rea:{connected:state.rea.connected,catalog:state.rea.tools.length>0,tools:state.rea.tools.map(t=>t.name)},
    target:{path:target,kind:QuixiAnalysis.targetKind(target,state.rea.targetIsDirectory,hint)},
    source:source?{id:source.id,connected:!!source.connected}:null,sources:analysisSources.items.map(x=>x.id),provider:$('rea-provider').value,
    opened:[...state.rea.opened].some(t=>QuixiAnalysis.sameTarget(t,target)),
    evidence:QuixiAnalysis.evidenceSummary(state.rea.records,target),
    last:record?.failed && (!record.target || QuixiAnalysis.sameTarget(record.target,target))?lastFailure(record):null,
    ida:{unsupported:ida.unsupported,installed:!!s.installed,enabled:!!s.enabled,connected:!!s.connected,session:!!s.session,allowAnnotations:!!s.allowAnnotations,
      reaUsesHeadless:!!s.reaUsesHeadless,registrationPath:s.registrationPath || '',registrationError:s.registrationError || ''},
    debugger:{connected:!!analysisSources.debugger.connected,sessionConnected:!!analysisSources.debugger.sessionConnected},
    specialist:{enabled:!!helperSettings.enabled,model:String(helperSettings.model || '').trim(),connection:helperConnections().some(p=>p.id===helperSettings.provider)},
    reconstruction:{brief:QuixiReconstruction.plans(state.runs,state.project,target).length>0,dossier,oracleCases:info?info.cases:null,approved:!!info?.approved,oracleStatus:oracle?.status || ''},
    dismissed:dismissedSteps()};
}
const guideActions={
  toolchain:async()=>{$('toolchain-dialog').showModal();await loadToolchain();},
  providers:async()=>showProviders(),
  helper:openHelperSetup,
  openOracleCases:async()=>{const dossier=$('reconstruction-dossier').value;if(!dossier)throw new Error('Select a saved specification first.');await openFile(`${dossier}/oracle-cases.json`);},
};
const stepLabel=step=>step.tool?`Select ${step.tool}`:step.action==='toolchain'?'Open Toolchain':step.action==='providers'?'Open Connections':step.action==='helper'?'Open helper setup':step.action==='openOracleCases'?'Open oracle-cases.json':'Show me';
// Take the user to the step: open its section, preselect its tool, scroll, focus and highlight. Never runs analysis.
async function goToStep(step){
  clearError();
  if(step.tool)await prepareReaTool(step.tool);
  if(step.action && guideActions[step.action]){await guideActions[step.action]();return;}
  const target=$(step.target);if(!target)return;
  window.QuixiWorkflow?.reveal(target,{scroll:false});
  if(target.tagName==='DETAILS')target.open=true;
  for(let d=target.parentElement?.closest('details');d;d=d.parentElement?.closest('details'))d.open=true;
  if(target.closest('[hidden]') && step.target==='code-rename'){
    // Annotation needs a decompiled function on screen: reopen the newest saved one for this target.
    const saved=QuixiAnalysis.filterHistory(state.rea.records,{target:state.rea.target}).find(r=>!r.failed && ['procedure_pseudo_code','decompile'].includes(r.tool));
    if(saved){const record=await pg('rea/evidence',{id:saved.id});selectRecord(record.id);renderEvidence(record);}
  }
  if(target.closest('[hidden]'))throw new Error(`${step.title}: that control is not shown in the current view. ${step.why}`);
  const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
  target.scrollIntoView({block:'center',behavior:reduce?'auto':'smooth'});
  if(!step.tool){const focus=target.tagName==='DETAILS'?target.querySelector('summary'):target;if(focus){if(!/^(BUTTON|INPUT|SELECT|TEXTAREA|SUMMARY|A)$/.test(focus.tagName))focus.tabIndex=-1;focus.focus({preventScroll:true});}}
  target.classList.remove('guide-pulse');void target.offsetWidth;target.classList.add('guide-pulse');setTimeout(()=>target.classList.remove('guide-pulse'),1600);
}
function guideButton(step,label,className){const b=el('button',label,className);b.type='button';b.title=step.why;b.onclick=()=>goToStep(step).catch(error);return b;}
function renderStages(stages){
  replace('re-stages',stages.map(st=>{const li=el('li',st.label,st.status);li.title=`${st.label} · ${st.status}: ${st.detail}`;if(st.status==='current')li.setAttribute('aria-current','step');return li;}));
}
function renderNext(steps){
  const box=$('re-next'),top=steps[0];$('re-guide-toggle').setAttribute('aria-pressed',String(guide.on));box.hidden=!guide.on || !top;
  if(!top){box.replaceChildren();return;}
  box.className=`re-next${top.kind==='config'?' config':''}`;
  const actions=el('div',undefined,'guide-actions'),later=el('button','Not now','small quiet');later.type='button';later.onclick=()=>dismissStep(top.id);
  actions.append(guideButton(top,stepLabel(top),'primary small'),later);
  const nodes=[el('div',top.kind==='config'?'Next · configuration':top.kind==='required'?'Next step':'Suggested next','eyebrow'),el('strong',top.title),el('p',top.why),actions];
  if(steps.length>1){const more=el('div',undefined,'guide-secondary');more.append(el('span','Also:'),...steps.slice(1).map(s=>guideButton(s,s.title,'small')));nodes.push(more);}
  box.replaceChildren(...nodes);
}
function renderPrompt(step){
  const box=$('re-prompt'),later=el('button','Not now','small quiet');later.type='button';later.onclick=()=>dismissStep(step.id);
  box.replaceChildren(el('span',`Next: ${step.title}`),guideButton(step,stepLabel(step),'small primary'),later);box.dataset.step=step.id;box.hidden=false;
}
function renderPreflight(id,result){
  const box=$(id),signature=result?`${result.message}|${result.step?.id || ''}`:'';
  if(guide.preflight[id]===signature)return;guide.preflight[id]=signature;
  if(!result){box.hidden=true;box.replaceChildren();return;}
  box.replaceChildren(el('div',result.message),...(result.step?[guideButton(result.step,result.step.title,'small')]:[]));box.hidden=false;
}
function refreshGuide(prompt=false){
  const snapshot=guideSnapshot(),stages=QuixiAnalysis.reStages(snapshot),steps=QuixiAnalysis.nextSteps(snapshot),signature=JSON.stringify([stages,steps,guide.on]);
  if(signature!==guide.signature){guide.signature=signature;renderStages(stages);renderNext(steps);}
  const top=steps[0];
  if(prompt){if(guide.on && top && top.id!==guide.top)renderPrompt(top);else if(!top)$('re-prompt').hidden=true;guide.top=top?.id || '';}
  else if(!$('re-prompt').hidden && !steps.some(s=>s.id===$('re-prompt').dataset.step))$('re-prompt').hidden=true;
  // Quick-action preflight: show the missing prerequisite with a way to complete it.
  let args={};try{args=JSON.parse($('rea-arguments').value) || {};}catch{/* Validation reports invalid JSON. */}
  renderPreflight('rea-preflight',state.rea.connected && $('rea-tool').value?QuixiAnalysis.preflight($('rea-tool').value,snapshot,args):null);
  const idaTool=ida.status?.tools?.find(t=>t.name===$('ida-tool').value);
  renderPreflight('ida-preflight',ida.status || ida.unsupported?QuixiAnalysis.idaPreflight(idaTool?.kind || 'read',snapshot):null);
}
on('re-guide-toggle','click',()=>{guide.on=!guide.on;storage(()=>localStorage.setItem('quixi.guide',guide.on?'on':'off'));if(!guide.on)$('re-prompt').hidden=true;refreshGuide();});
on('debugger-setup','click',async()=>{const result=await pg('toolchain/bridge-install-command',{id:'x64dbg-bridge'});showView('overview');showConsole('terminal');$('terminal-command').value=result.command;});

// Events
on('received-code-open','click',async()=>{const p=pendingCode();if(!p || !await selectProject(p.id))return;if(p.received.purpose==='analysis'){await selectArtifact({path:p.received.analysisTarget});showView('analysis');}else{await openFile(p.received.entryPath);}});
on('received-code-dismiss','click',()=>{const p=pendingCode();if(p)markReceivedSeen(p.id);});
for(const b of document.querySelectorAll('[data-view]'))b.onclick=()=>showView(b.dataset.view);
for(const b of document.querySelectorAll('[data-console]'))b.onclick=()=>showConsole(b.dataset.console);
for(const b of document.querySelectorAll('[data-prompt]'))b.onclick=()=>{$('task').value=b.dataset.prompt;$('task').focus();};
for(const b of document.querySelectorAll('[data-rea-tool]'))b.onclick=()=>prepareReaTool(b.dataset.reaTool).catch(error);
on('reconstruction-analyse','click',()=>busy($('reconstruction-analyse'),()=>prepareReconstruction('plan'),'Preparing…'));on('reconstruction-build','click',()=>busy($('reconstruction-build'),()=>prepareReconstruction('build'),'Preparing…'));
on('reconstruction-export','click',()=>busy($('reconstruction-export'),async()=>{const input=reconstructionInput('plan');QuixiReconstruction.prompt(input);await saveDossier(input);},'Saving dossier…'));
function closeOracleConsent(){state.rea.oraclePreview=null;$('oracle-consent').hidden=true;replace('oracle-consent-cases',[]);}
on('reconstruction-dossier','change',()=>{state.rea.oracle=null;$('oracle-result').hidden=true;closeOracleConsent();renderReconstruction();return refreshOracleInfo();});
// Oracle consent: the exact commands, expectations and file hash are shown in-page before anything runs.
function renderOracleConsent(config,preview){
  const plan=QuixiAnalysis.oraclePlan(preview);state.rea.oracleInfo={dossier:$('reconstruction-dossier').value,cases:plan.cases.length,approved:plan.approved};state.rea.oraclePreview={config,sha256:plan.sha256,approved:plan.approved,dossier:$('reconstruction-dossier').value};
  $('oracle-consent-note').textContent=plan.empty?'This suite declares no cases. Running it records an UNVERIFIED result.':
    `${plan.cases.length} case(s) from ${show(config)} will run on this computer with your Windows user permissions.${plan.approved?' You approved this exact file before and it is unchanged.':plan.changed?' This file changed since you last approved it.':' Approval applies only to this exact file content.'}`;
  $('oracle-consent-sha').textContent=`SHA-256 ${plan.sha256 || 'unavailable'}`;
  replace('oracle-consent-cases',plan.cases.map(c=>{
    const n=el('div',undefined,'oracle-case');n.append(el('strong',c.name),el('p',c.form==='argv'?'Program and arguments (argv, shown quoted)':'Command','field-note'),el('pre',c.missing?'(no command declared)':c.command));
    if(c.expectations.length){const ul=el('ul');for(const x of c.expectations)ul.append(el('li',x));n.append(ul);}else n.append(el('p','No expected outputs declared.','analysis-error'));
    return n;}));
  $('oracle-approve').textContent=plan.approved?'Run approved checks':'Approve & run';$('oracle-approve').disabled=!plan.valid;
  $('oracle-consent').hidden=false;$('oracle-approve').focus();
}
on('oracle-run','click',()=>busy($('oracle-run'),async()=>{
  if($('mode').value!=='code')throw new Error('Select Code mode in the sidebar to execute the reviewed oracle commands.');
  const config=`${$('reconstruction-dossier').value}/oracle-cases.json`;let preview;
  try{preview=await pg('oracle-preview',{config});}catch(e){if(unsupported(e))throw new Error('This build cannot show the oracle commands for review, so nothing was run. Update REA Studio to run oracle checks.');throw e;}
  renderOracleConsent(config,preview);
},'Loading cases…'));
on('oracle-cancel','click',closeOracleConsent);
on('oracle-approve','click',()=>busy($('oracle-approve'),async()=>{
  const p=state.rea.oraclePreview;if(!p || p.dossier!==$('reconstruction-dossier').value)throw new Error('Review the oracle cases again before running them.');
  if($('mode').value!=='code')throw new Error('Select Code mode in the sidebar to execute the reviewed oracle commands.');
  if(running() || state.rea.oracleOperation)throw new Error('Finish the active task or oracle checks first.');
  if(!p.approved)await pg('oracle-approve',{config:p.config,sha256:p.sha256});
  const operation={id:crypto.randomUUID(),project:state.project};state.rea.oracleOperation=operation;state.rea.oracle=null;
  closeOracleConsent();$('oracle-result').hidden=false;$('oracle-result').textContent='Running the approved checks…';$('oracle-stop').disabled=false;renderReconstruction();updateControls();
  try{const result=await api('oracle-run',{project:operation.project,operationId:operation.id,mode:'code',config:p.config});
    state.rea.oracle=result;$('oracle-result').textContent=show(JSON.stringify(result,null,2),true);refreshGuide(true);await loadFiles();
  }catch(e){$('oracle-result').textContent=e.message;throw e;}
  finally{state.rea.oracleOperation=null;renderReconstruction();updateControls();}
},'Running checks…'));
on('oracle-stop','click',()=>busy($('oracle-stop'),async()=>{const operation=state.rea.oracleOperation;if(!operation)return;await api('oracle-stop',{project:operation.project,operationId:operation.id});if(state.rea.oracleOperation?.id===operation.id)$('oracle-result').textContent='Stopping checks and their child processes…';},'Stopping…'));
on('oracle-retry','click',()=>prepareReconstruction('retry'));
on('toolchain-open','click',async()=>{$('toolchain-dialog').showModal();await loadToolchain();});on('toolchain-close','click',()=>$('toolchain-dialog').close());on('toolchain-refresh','click',loadToolchain);
on('rea-restart','click',()=>busy($('rea-restart'),async()=>{if(running())throw new Error('Finish the active task before restarting its analysis plugin.');await pg('rea/disconnect');state.rea.connected=false;state.rea.opened.clear();await connectRea();},'Restarting…'));
on('workflow-read','click',()=>readWorkflow());on('workflow-next','click',()=>readWorkflow(workflowOffset));on('workflow-guide','change',()=>{$('workflow-next').disabled=true;});
// Changing the provider only updates open_binary's provider_id; edited JSON arguments are kept.
on('rea-provider','change',()=>{
  const tool=state.rea.tools.find(t=>t.name===$('rea-tool').value);if(tool?.name!=='open_binary' || !tool.inputSchema?.properties?.provider_id)return;
  let args;try{args=JSON.parse($('rea-arguments').value);}catch{return;}if(!args || typeof args!=='object' || Array.isArray(args))return;
  if($('rea-provider').value)args.provider_id=$('rea-provider').value;else delete args.provider_id;
  $('rea-arguments').value=JSON.stringify(args,null,2);syncAnalysisInputs();
});
on('theme','click',()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;localStorage.setItem('quixi.theme',theme);});
// Responsive panel toggles are owned by workflow.js.
on('open-project','click',()=>busy($('open-project'),async()=>{if(!guardDirty())return;const project=await pg('project');if(!project.cancelled){await refreshState();await selectProject(project.id);}}));
on('project','change',()=>selectProject($('project').value));on('refresh','click',loadFiles);let filterTimer;on('filter','input',()=>{clearTimeout(filterTimer);filterTimer=setTimeout(()=>loadFiles().catch(error),180);});
// A new file has no hash: it stays saveable (even when empty) and the backend refuses an existing path.
on('new-file','click',async()=>{requireProject();if(!guardDirty())return;const path=await askText('Create a file','Path relative to the selected project');if(!path)return;state.file={path,content:'',hash:'',lineEnding:'lf',bom:false};state.dirty=true;disk.pending=null;$('disk-bar').hidden=true;renderEditor();showView('code');$('editor').focus();});
on('editor','input',()=>{state.dirty=!!state.file && (!state.file.hash || $('editor').value!==state.file.content);updateEditor();});on('editor','scroll',()=>$('lines').scrollTop=$('editor').scrollTop);
// Tab inserts the file's indentation through the editing pipeline so Ctrl+Z undoes it; Shift+Tab keeps moving focus.
on('editor','keydown',e=>{if(e.key!=='Tab' || e.shiftKey || e.ctrlKey || e.altKey || e.metaKey)return;e.preventDefault();const t=e.target,text=QuixiAnalysis.indentUnit(state.file?.path,t.value);
  if(!document.execCommand?.('insertText',false,text)){t.setRangeText(text,t.selectionStart,t.selectionEnd,'end');t.dispatchEvent(new Event('input'));}});
on('save','click',()=>saveFile());on('refresh-diff','click',loadDiff);
on('diff-more','click',()=>renderDiff('diff','',false,true));on('run-diff-more','click',()=>renderDiff('run-diff','',false,true));
on('disk-reload','click',()=>{if(disk.pending)loadEditorFile(disk.pending,true);});
on('disk-keep','click',()=>{if(disk.pending)return saveFile({hash:disk.pending.hash});});
on('disk-diff','click',()=>{if(!disk.pending)return;const lines=QuixiAnalysis.lineDiff(disk.pending.content,$('editor').value),out=$('disk-diff-output');out.hidden=false;
  out.replaceChildren(el('span','--- on disk  +++ your buffer','hunk'),...(lines?lines.map(l=>el('span',l.text,l.cls)):[el('span','The files are too large to compare here. Reload to see the disk version, or keep yours.','hunk')]));});
on('discard-cancel','click',()=>{gitView.discard=null;$('discard-confirm').hidden=true;});
on('discard-approve','click',()=>busy($('discard-approve'),async()=>{const paths=gitView.discard;if(!paths)return;await gitAction('git-discard',{paths,confirm:true});gitView.discard=null;$('discard-confirm').hidden=true;if(state.file && paths.includes(state.file.path))await checkDisk();},'Discarding…'));
on('commit-form','submit',e=>{e.preventDefault();return busy($('commit'),async()=>{const message=$('commit-message').value.trim();if(!message)throw new Error('Enter a commit message.');
  let result;try{result=await pg('git-commit',{message});}catch(err){if(unsupported(err))throw new Error('This build cannot commit from REA Studio yet.');throw err;}
  $('commit-output').hidden=false;$('commit-output').textContent=show(result.output || (result.ok?'Committed.':'Commit failed.'),true);if(result.ok)$('commit-message').value='';await loadFiles();await loadDiff();},'Committing…');});
on('run-filter','input',renderRuns);
on('run-continue','click',()=>{const run=selectedRun();if(!run)return;state.continueFrom=run.id;
  const match=Array.from($('model').querySelectorAll('option')).find(o=>o.dataset.model===run.model && (!run.provider || o.dataset.provider===run.provider));if(match){$('model').value=match.value;$('model').dispatchEvent(new Event('change'));}
  if(['ask','code'].includes(run.mode)){$('mode').value=run.mode;$('mode').dispatchEvent(new Event('change'));}$('task').value='';renderContinue();$('task').focus();});
on('continue-clear','click',()=>{state.continueFrom='';renderContinue();$('task').focus();});
on('approval-approve','click',()=>busy($('approval-approve'),async()=>{const run=selectedRun();if(run?.status!=='awaiting_approval')return;await runRoute('run-approve',{id:run.id,command:runView.command},'This build cannot approve commands; stop the run instead.');await refreshState();},'Approving…'));
on('approval-deny','click',()=>busy($('approval-deny'),async()=>{const run=selectedRun();if(run?.status!=='awaiting_approval')return;await runRoute('run-deny',{id:run.id,command:runView.command,reason:$('approval-reason').value.trim()},'This build cannot deny commands; stop the run instead.');await refreshState();},'Denying…'));
on('run-revert-all','click',()=>{const run=selectedRun();if(run)return busy($('run-revert-all'),()=>revertRun(run.id),'Reverting…');});
on('run-revert-force','click',()=>{const p=runView.pending;if(p)return busy($('run-revert-force'),()=>revertRun(p.id,p.paths,true),'Reverting…');});
on('run-revert-cancel','click',()=>{runView.pending=null;$('run-revert-confirm').hidden=true;});
on('confirm-commands','change',()=>storage(()=>localStorage.setItem('quixi.confirm-commands',$('confirm-commands').value)));
on('console-expand','click',()=>$('console').classList.toggle('expanded'));
on('new-run','click',()=>{state.run='';state.continueFrom='';renderContinue();$('task').value='';showView('overview');renderRuns();$('task').focus();});on('task-form','submit',startTask);
on('stop','click',async()=>{const active=running();if(active){await pg('cancel',{id:active.id});await refreshState();}});
on('mode','change',()=>{$('access-note').textContent=$('mode').value==='code'?'Code mode can edit files and run commands with your Windows user permissions.':'Ask mode can inspect project files and answer questions.';updateControls();});
on('model','change',()=>{localStorage.setItem('quixi.model',$('model').value);$('selected-model').textContent=$('model').selectedOptions[0]?.dataset.model || '';renderModelsDiagram();updateControls();refreshGuide();});
// Terminal: streamed jobs with scrollback per project (session only), command recall and the backend's persistent cwd.
const terminals=new Map(),termNodes=new WeakMap();
const termKey=project=>`quixi.terminal.${project}`;
function terminalFor(project){
  if(!terminals.has(project)){const saved=storage(()=>JSON.parse(sessionStorage.getItem(termKey(project)) || 'null'),null);
    terminals.set(project,{entries:Array.isArray(saved?.entries)?saved.entries.filter(e=>e && typeof e.command==='string').map(e=>({...e,done:true})):[],history:Array.isArray(saved?.history)?saved.history:[],cwd:typeof saved?.cwd==='string'?saved.cwd:'',index:-1,draft:'',job:null});}
  const t=terminals.get(project);if(t.index<0)t.index=t.history.length;return t;
}
function saveTerminal(project){const t=terminals.get(project);if(!t)return;storage(()=>sessionStorage.setItem(termKey(project),JSON.stringify({cwd:t.cwd,history:t.history,entries:t.entries.slice(-200).map(e=>({...e,parts:e.parts.map(p=>({stream:p.stream,text:p.text.length>20000?`${p.text.slice(0,10000)}\n…\n${p.text.slice(-10000)}`:p.text}))}))})));}
function terminalEntryNode(entry){
  const n=termNodes.get(entry) || el('div',undefined,'term-entry');termNodes.set(entry,n);
  const out=el('pre',undefined,'term-out');out.append(...entry.parts.map(p=>el('span',show(p.text,true),p.stream==='stderr'?'term-stderr':'')));
  const status=entry.done?`Exit code: ${entry.exitCode ?? 'unknown'}${entry.timedOut?' (timed out)':''}${entry.stopped?' · stopped':''}`:'Running…';
  n.replaceChildren(el('div',`${entry.cwd?`${show(entry.cwd)} `:''}› ${show(entry.command)}`,'term-command'),...(entry.parts.length?[out]:[]),
    ...(entry.truncated?[el('p','Output truncated (head + tail kept).','term-note')]:[]),el('p',status,`term-note${entry.done && entry.exitCode!==0?' term-failed':''}`));
  return n;
}
function renderTerminal(){
  const t=state.project?terminalFor(state.project):null,log=$('terminal-output');
  log.replaceChildren(...(t?.entries.length?t.entries.map(terminalEntryNode):[el('p','Ready.','empty')]));log.scrollTop=log.scrollHeight;
  const cwd=t?.cwd || '';$('terminal-cwd').textContent=cwd?`${cwd.replaceAll('\\','/').split('/').filter(Boolean).slice(-2).join('/')} ›`:'›';$('terminal-cwd').title=cwd || 'Working directory';
  $('terminal-stop').hidden=!t?.job;$('terminal-send').disabled=!!t?.job;
}
function updateTerminalEntry(project,entry){if(project!==state.project)return;const log=$('terminal-output'),stick=log.scrollHeight-log.scrollTop-log.clientHeight<40;terminalEntryNode(entry);if(stick)log.scrollTop=log.scrollHeight;}
async function runTerminal(command){
  requireProject();const project=state.project,t=terminalFor(project);if(t.job)throw new Error('Wait for the running command or stop it first.');
  t.history=QuixiAnalysis.rememberCommand(t.history,command);t.index=t.history.length;t.draft='';
  const entry={command,cwd:t.cwd,parts:[],done:false,exitCode:null,truncated:false};t.entries.push(entry);if(t.entries.length>200)t.entries.splice(0,t.entries.length-200);
  t.job={id:'',entry};renderTerminal();
  try{
    let job;
    try{job=(await api('command-start',{project,command})).job;}catch(e){
      if(!unsupported(e))throw e;
      // Older builds run the command in one blocking request.
      const r=await api('command',{project,command});
      Object.assign(entry,{exitCode:r.exitCode ?? null,timedOut:!!r.timedOut,truncated:!!r.truncated,parts:QuixiAnalysis.appendChunks([],[{stream:'stdout',text:r.stdout || ''},{stream:'stderr',text:r.stderr || ''}])});return;
    }
    t.job.id=job;let offset=0;
    for(;;){
      const r=await api('command-poll',{project,job,offset});
      entry.parts=QuixiAnalysis.appendChunks(entry.parts,r.chunks);offset=r.nextOffset ?? offset;entry.truncated=!!r.truncated;if(typeof r.cwd==='string' && r.cwd)t.cwd=r.cwd;
      if(r.done){entry.exitCode=r.exitCode ?? null;break;}
      updateTerminalEntry(project,entry);await new Promise(resolve=>setTimeout(resolve,300));
    }
  }catch(e){entry.parts=QuixiAnalysis.appendChunks(entry.parts,[{stream:'stderr',text:`\n${e.message}`}]);throw e;}
  finally{entry.done=true;t.job=null;saveTerminal(project);if(project===state.project)renderTerminal();if(project===state.project)loadFiles().catch(error);}
}
on('terminal-form','submit',e=>{e.preventDefault();const command=$('terminal-command').value.trim();if(!command)return;$('terminal-command').value='';return runTerminal(command);});
on('terminal-command','keydown',e=>{if(!['ArrowUp','ArrowDown'].includes(e.key) || e.altKey || e.ctrlKey || e.metaKey || !state.project)return;const t=terminalFor(state.project);
  if(t.index===t.history.length)t.draft=$('terminal-command').value;const r=QuixiAnalysis.recallCommand(t.history,t.index,e.key==='ArrowUp'?-1:1,t.draft);t.index=r.index;e.preventDefault();$('terminal-command').value=r.value;});
on('terminal-stop','click',async()=>{const t=state.project && terminals.get(state.project);if(!t?.job?.id)return;t.job.entry.stopped=true;try{await api('command-stop',{project:state.project,job:t.job.id});}catch(e){if(unsupported(e))throw new Error('This build cannot stop a running command.');throw e;}});
on('providers','click',showProviders);on('configure','click',showProviders);on('close-provider','click',()=>$('provider-dialog').close());on('provider-id','change',fillProvider);
on('provider-form','submit',e=>{e.preventDefault();const button=e.submitter || $('provider-form').querySelector('button.primary');return connectionAction(button,async()=>{
  const form=providerFormData(),previous=(state.providers.providers || []).find(p=>p.id===form.providerId),chosen=$('model').selectedOptions[0];
  const updateRole=chosen?.dataset.provider===form.providerId && chosen?.dataset.model===previous?.selectedModel;
  const name=$('provider-id').selectedOptions[0]?.textContent.replace(/ · configured$/,'') || 'Connection';
  await providerApi('/save',form);$('api-key').value='';
  if(updateRole){$('model').value='';localStorage.setItem('quixi.model',`${form.providerId}::${form.selectedModel}`);}
  await refreshState();showProviders();$('provider-message').textContent=`${name} saved. ${updateRole?'Agent model updated to the selected connection model.':'Choose the Agent model in the Models card.'} The Decompile helper can use any OpenAI-compatible connection.`;
},'Saving…');});
on('connection-add','click',()=>{const next=(state.providers.providers || []).find(p=>!p.configured);if(next)editConnection(next.id);else $('provider-id').focus();});
on('test-provider','click',()=>connectionAction($('test-provider'),async()=>{const result=await providerApi('/test',providerFormData());$('provider-message').textContent=`${result.ok?'Connected':'Connection failed'}: ${show(result.message || JSON.stringify(result))}`;if(result.discoveredModels)replace('provider-models',result.discoveredModels.map(m=>option(m,m)));await refreshState();renderConnections();},'Testing…'));
on('detect-local','click',()=>connectionAction($('detect-local'),async()=>{const result=await providerApi('/detect-local',{});$('provider-message').textContent=JSON.stringify(result,null,2);await refreshState();renderConnections();},'Detecting…'));
on('open-bench','click',()=>pg('open-bench'));
on('show-analysis','click',()=>showView('analysis'));on('rea-connect','click',()=>busy($('rea-connect'),connectRea,'Connecting…'));
on('rea-runtime','change',()=>busy($('rea-connect'),connectRea,'Connecting…'));
on('rea-runtime-save','click',()=>busy($('rea-runtime-save'),saveRuntimeSettings,'Saving & restarting…'));
on('artifact-file','click',()=>selectArtifact({}));on('artifact-folder','click',()=>selectArtifact({directory:true}));on('artifact-set-path','click',async()=>{const path=await askText('Select an artifact','Absolute path to a file or application folder',state.rea.target);if(path)await selectArtifact({path});});
on('rea-search','input',()=>renderTools(undefined,true));on('rea-tool','change',toolChanged);on('rea-form','submit',runRea);on('rea-arguments','input',syncAnalysisInputs);
on('rea-close','click',()=>executeAnalysis('close_binary',{},false));
on('rea-record','change',async()=>{const id=$('rea-record').value,t=recordSeq.next();if(!id)return;const record=await pg('rea/evidence',{id});if(recordSeq.current(t) && $('rea-record').value===id)renderEvidence(record);});
on('rea-use','click',()=>{if(!state.rea.record)return;const r=state.rea.record;$('rea-enabled').checked=true;$('task').value=`Use the saved analysis record ${r.id} (${r.provider || 'rea'} / ${r.tool}, ${r.kind || 'static'}) for ${r.target}. Explain the observed behaviour, cite record IDs and any provider Evidence IDs, distinguish recorded runtime observations, imported reports, inferences and limitations, and suggest the next implementation step in this project.`;showView('overview');$('task').focus();});
on('rea-export','click',async()=>{if(!state.rea.record)return;const result=await pg('rea/export',{id:state.rea.record.id});if(result.path)$('rea-health').textContent=`Evidence exported to ${result.path}`;});
on('rea-enabled','change',async()=>{if($('rea-enabled').checked){try{if(!state.rea.connected)await connectRea();}catch(e){$('rea-enabled').checked=false;throw e;}}});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();saveFile().catch(error);}if((e.ctrlKey||e.metaKey)&&e.key==='Enter' && !document.querySelector('dialog[open]')){e.preventDefault();if(!$('start').disabled)$('task-form').requestSubmit();}
  // Alt+Left/Right walk decompiled-function history instead of navigating the WebView.
  if(e.altKey && !e.ctrlKey && (e.key==='ArrowLeft' || e.key==='ArrowRight') && !$('view-analysis').hidden && !document.querySelector('dialog[open]')){e.preventDefault();navigate(e.key==='ArrowLeft'?-1:1).catch(error);}});
window.addEventListener('beforeunload',e=>{if(state.dirty){e.preventDefault();e.returnValue='';}});
document.documentElement.dataset.theme=localStorage.getItem('quixi.theme') || 'dark';
$('confirm-commands').value=storage(()=>localStorage.getItem('quixi.confirm-commands'),null) || 'risky';if(!$('confirm-commands').value)$('confirm-commands').value='risky';
(async()=>{try{await refreshState();renderTerminal();await loadFiles();await loadAnalysisHistory();await refreshAnalysisSources();await loadDecompileSettings();}catch(e){error(e);$('connection').classList.add('offline');$('connection').textContent='Disconnected';}
  async function poll(){try{const previous=running();await refreshState();await checkDisk();if(!$('view-analysis').hidden || $('toolchain-dialog').open)await refreshConnectionBadges();if(!$('view-analysis').hidden && !state.rea.operation)await refreshIda().catch(()=>{});if(previous && !running()){await loadFiles();await loadAnalysisHistory();}}catch(e){$('connection').classList.add('offline');$('connection').textContent='Disconnected';}finally{setTimeout(poll,running()?1200:7000);}}setTimeout(poll,7000);
})();
