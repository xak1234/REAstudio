/* Project-scoped, immutable snapshots of related artifacts. */
'use strict';
(() => {
  let project = '', generation = 0, locked = false, summaries = [], inspected = null, exported = null;
  const selected = () => $('inv-select').value;
  const message = (text, failed = false) => { $('inv-status').textContent = text; $('inv-status').classList.toggle('analysis-error', failed); };
  const pathKey = path => /^[a-z]:|^\\\\/i.test(path) ? path.replaceAll('\\','/').toLowerCase() : path;
  function targets() { return [...new Map($('inv-targets').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean).map(path => [pathKey(path),path])).values()]; }
  function controls() {
    for (const id of ['inv-name','inv-targets','inv-add-selected','inv-add-history','inv-create','inv-refresh','inv-select','inv-check','inv-export','inv-delete']) $(id).disabled = locked || !state.project;
    $('inv-add-selected').disabled ||= !state.rea.target || state.rea.targetIsDirectory;
    $('inv-select').disabled ||= !summaries.length;
    $('inv-check').disabled ||= !selected(); $('inv-delete').disabled ||= !selected();
    $('inv-export').disabled ||= !inspected?.readyToExport || inspected.investigation?.id !== selected();
    $('inv-open-manifest').hidden = !exported || exported.project !== state.project;
    $('inv-open-manifest').disabled = locked;
    document.querySelectorAll('#inv-rows button').forEach(button => { button.disabled = locked || !!running() || !!state.rea.operation; });
    updateControls();
  }
  function clearInspection() {
    inspected = null; $('inv-rows').replaceChildren();
    $('inv-summary').textContent = selected() ? 'Check the saved snapshot against the files currently on disk.' : 'Choose a saved investigation or capture a new one.';
  }
  function syncProject() {
    if (project === state.project) return;
    project = state.project; generation++; summaries = []; exported = null;
    $('inv-select').replaceChildren(option('', 'No saved investigations'));
    $('inv-name').value = ''; $('inv-targets').value = ''; clearInspection(); message('');
  }
  async function call(action, data, token) {
    const result = await api('investigation/' + action, {project:token.project, ...data});
    if (state.project !== token.project || generation !== token.generation) throw new Error('The project changed; this result belongs to the earlier project.');
    return result;
  }
  async function operation(label, action) {
    if (locked) return;
    requireProject(); syncProject(); locked = true; controls(); message(label);
    const token = {project:state.project, generation};
    try { return await action(token); }
    catch (e) { message(e.message || String(e), true); }
    finally { locked = false; controls(); }
  }
  async function list(token, choose) {
    const result = await call('list', {}, token);
    summaries = result.investigations || [];
    const old = choose || selected();
    $('inv-select').replaceChildren(...(summaries.length ? summaries.map(item => option(item.id, item.name + ' · ' + item.artifactCount + ' files · ' + new Date(item.created).toLocaleString())) : [option('', 'No saved investigations')]));
    if (summaries.some(item => item.id === old)) $('inv-select').value = old;
    if (inspected?.investigation?.id !== selected()) clearInspection();
    controls();
  }
  function renderInspection(result) {
    inspected = result;
    $('inv-rows').replaceChildren(...result.artifacts.map(item => {
      const row = el('tr', undefined, 'investigation-artifact'); row.dataset.status = item.status; row.dataset.target = item.target;
      const file = el('td'), choose = el('button', item.target.split(/[\\/]/).pop(), 'link');
      choose.type = 'button'; choose.title = item.target; choose.disabled = locked;
      choose.addEventListener('click', () => selectArtifact({path:item.target}).catch(error));
      file.append(choose, el('small', item.target, 'inv-path'));
      const hash = el('td'), code = el('code', (item.pinnedIdentity?.sha256 || '').slice(0,16)); code.title = item.pinnedIdentity?.sha256 || ''; hash.append(code);
      const status = el('td', item.status); status.className = item.status === 'current' ? 'inv-current' : 'analysis-error';
      const evidence = el('td', String(item.matchingRecordCount || 0));
      evidence.title = (item.failedRecordCount || 0) + ' failed records; ' + (item.modelSuggestionCount || 0) + ' model suggestions; ' + (item.excludedRecordCount || 0) + ' excluded records';
      row.append(file, hash, status, evidence); return row;
    }));
    const count = result.totalMatchingRecordCount || 0;
    $('inv-summary').textContent = result.artifacts.length + ' files · ' + count + ' matching evidence records · Checked ' + new Date(result.checkedAt).toLocaleString() + '. ' + (result.readyToExport ? 'Ready to export this evidence bundle.' : !result.allArtifactsCurrent ? 'Some files changed or are unavailable. Keep this snapshot and capture a new one for a different build.' : 'Run analysis on these files before exporting; no matching evidence is saved yet.');
  }
  async function inspect(token) {
    const result = await call('inspect', {id:selected()}, token); renderInspection(result); controls();
    message(result.readyToExport ? 'Snapshot checked. Export rechecks every file before publishing the bundle.' : 'Snapshot checked. Review the file status below.');
  }
  async function refresh() {
    if (locked) return;
    syncProject(); controls(); if (!state.project) return;
    await operation('Loading saved investigations…', async token => { await list(token); message(''); });
  }
  function add(paths) {
    const values = targets(); const known = new Set(values.map(pathKey));
    for (const path of paths) if (path && !known.has(pathKey(path))) { values.push(path); known.add(pathKey(path)); }
    if (values.length > 32) throw new Error('An investigation can contain at most 32 files. Choose the modules you need.');
    $('inv-targets').value = values.join('\n');
  }
  $('inv-add-selected').addEventListener('click', () => { try { add([state.rea.target]); } catch(e) { message(e.message, true); } });
  $('inv-add-history').addEventListener('click', () => {
    try { add((state.rea.artifactGroups || []).filter(group => (group.artifactIdentity || group.identity || group).kind === 'file').map(group => group.target || group.path)); }
    catch(e) { message(e.message, true); }
  });
  $('inv-create').addEventListener('click', () => operation('Capturing file identities…', async token => {
    const name = $('inv-name').value.trim(), paths = targets();
    if (!name || !paths.length) throw new Error('Enter a name and at least one file path.');
    const result = await call('create', {name,targets:paths}, token);
    await list(token, result.investigation.id); await inspect(token);
  }));
  $('inv-refresh').addEventListener('click', () => refresh().catch(error));
  $('inv-select').addEventListener('change', () => { clearInspection(); controls(); if(selected()) operation('Checking files and matching evidence…', inspect); });
  $('inv-check').addEventListener('click', () => operation('Checking files and matching evidence…', inspect));
  $('inv-export').addEventListener('click', () => operation('Verifying files and exporting evidence…', async token => {
    const result = await call('export', {id:selected()}, token);
    exported = {project:token.project, path:result.relativePath};
    message('Saved ' + result.relativePath + ' · ' + result.artifactCount + ' files · ' + result.recordCount + ' records · ' + result.excludedRecordCount + ' exclusions recorded.');
    await loadFiles();
  }));
  $('inv-delete').addEventListener('click', () => {
    const item = summaries.find(value => value.id === selected()); if (!item) return;
    if (!window.confirm('Delete the saved snapshot “' + item.name + '”? Exported bundles, original files and analysis evidence will remain.')) return;
    operation('Deleting the saved snapshot…', async token => { await call('delete',{id:item.id},token); clearInspection(); await list(token); message('Saved snapshot deleted. Existing exports and evidence were preserved.'); });
  });
  $('inv-open-manifest').addEventListener('click', () => {
    if (exported?.project === state.project) openFile(exported.path.replaceAll('\\','/') + '/manifest.json').catch(error);
  });
  window.QuixiInvestigations = {get busy() { return locked; }, refresh, updateCandidates:controls};
  $('inv-panel').addEventListener('toggle', () => { if ($('inv-panel').open) refresh().catch(error); });
  window.addEventListener('rea-project-changed', () => refresh().catch(error));
  refresh().catch(error);
})();
