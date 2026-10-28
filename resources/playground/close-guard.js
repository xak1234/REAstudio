/* Native-window close negotiation. Only the host can issue a valid close nonce. */
'use strict';
(() => {
  const dialog = $('native-close-dialog');
  let request = null, timer = 0, saving = false, closing = false;
  const post = (type, extra = {}) => {
    if (!request || !window.ipc?.postMessage) return false;
    window.ipc.postMessage(JSON.stringify({type, nonce:request.nonce, ...extra}));
    return true;
  };
  const activeWork = () => !!(request?.activeWork || state.busy || running() || state.rea.operation || state.rea.connecting || state.rea.oracleOperation || window.QuixiInvestigations?.busy || [...terminals.values()].some(t => t.job));
  function reset() {
    request = null; saving = false; closing = false; clearInterval(timer); timer = 0;
    if (dialog.open) dialog.close();
  }
  function reply(action) {
    if (closing) return;
    if (action === 'close' && (saving || editorState.saving)) return;
    if (!post('rea-close-response', {action})) {
      $('native-close-error').hidden = false;
      $('native-close-error').textContent = 'The native window could not be reached. Your editor remains open.';
      return;
    }
    if (action === 'cancel') reset();
    else {
      closing = true; clearInterval(timer); timer = 0;
      if (!dialog.open) dialog.showModal();
      render();
    }
  }
  function render() {
    if (!request) return;
    $('native-close-cancel').disabled = closing;
    if (closing) {
      $('native-close-note').textContent = 'Closing REA Studio…';
      $('native-close-save').disabled = true;
      $('native-close-discard').disabled = true;
      return;
    }
    const pending = saving || editorState.saving;
    const notes = [];
    if (state.dirty) notes.push('The editor has unsaved changes' + (state.file?.path ? ' in ' + state.file.path : '') + '.');
    if (pending) notes.push('A save is in progress. Wait for it to finish before closing.');
    if (activeWork()) notes.push('Closing will stop running tasks, commands and analysis.');
    if (!notes.length) notes.push('Your editor changes are saved.');
    $('native-close-note').textContent = notes.join(' ');
    $('native-close-save').hidden = !state.dirty;
    $('native-close-save').disabled = pending || !state.file;
    $('native-close-discard').disabled = pending;
    $('native-close-discard').textContent = state.dirty ? 'Close without saving' : 'Close';
  }
  window.addEventListener('rea-native-close-request', event => {
    const detail = event.detail;
    if (!detail || typeof detail.nonce !== 'string' || !/^[a-f0-9-]{36}$/i.test(detail.nonce)) return;
    if (request?.nonce === detail.nonce) { post('rea-close-ready'); render(); return; }
    reset(); request = {nonce:detail.nonce, activeWork:!!detail.activeWork};
    if (!post('rea-close-ready')) { reset(); return; }
    if (!state.dirty && !editorState.saving && !activeWork()) { reply('close'); return; }
    $('native-close-error').hidden = true;
    render(); dialog.showModal(); $('native-close-cancel').focus();
    timer = setInterval(render, 100);
  });
  window.addEventListener('rea-native-close-cancelled', event => {
    if (request?.nonce === event.detail?.nonce) reset();
  });
  dialog.addEventListener('cancel', event => { event.preventDefault(); reply('cancel'); });
  $('native-close-cancel').addEventListener('click', () => reply('cancel'));
  $('native-close-discard').addEventListener('click', () => reply('close'));
  $('native-close-save').addEventListener('click', async () => {
    if (!request || saving || editorState.saving || !state.file) return;
    const nonce = request.nonce, project = state.project, path = state.file.path;
    saving = true; $('native-close-error').hidden = true; render();
    try {
      await saveFile();
      if (request?.nonce !== nonce) return;
      if (state.project !== project || state.file?.path !== path || state.dirty || editorState.saving) {
        throw new Error('The editor changed while saving. Review the current buffer before closing.');
      }
      saving = false; reply('close');
    } catch (e) {
      if (request?.nonce === nonce) {
        $('native-close-error').textContent = e.message || String(e);
        $('native-close-error').hidden = false;
      }
    } finally { saving = false; render(); }
  });
})();
