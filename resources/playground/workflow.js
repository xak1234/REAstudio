/* Workspace layout and progressive disclosure; no analysis or permissions are changed. */
'use strict';
(() => {
  const mobile = matchMedia('(max-width:1000px)');
  const panels = ['explorer', 'settings'];
  const remembered = (key, fallback) => { try { return localStorage.getItem(key) || fallback; } catch { return fallback; } };
  const remember = (key, value) => { try { localStorage.setItem(key, value); } catch { /* Layout remains usable without storage. */ } };
  const desktop = {explorer:remembered('rea.ui.explorer', 'open') === 'open', settings:remembered('rea.ui.settings', 'closed') === 'open'};
  let overlay = '', expert = remembered('rea.ui.expert', 'false') === 'true';
  const button = id => $(id + '-toggle');
  function renderPanels() {
    for (const id of panels) {
      const open = mobile.matches ? overlay === id : desktop[id];
      document.body.classList.toggle(id + '-collapsed', !desktop[id]);
      $(id).classList.toggle('show', mobile.matches && open);
      $(id).inert = !open;
      button(id).setAttribute('aria-expanded', String(open));
      button(id).setAttribute('aria-controls', id);
    }
    $('panel-backdrop').hidden = !mobile.matches || !overlay;
    document.body.classList.toggle('panel-overlay-open', mobile.matches && !!overlay);
  }
  function setPanel(id, open, focus = false) {
    if (!panels.includes(id)) return;
    const active = document.activeElement;
    if (mobile.matches) overlay = open ? id : overlay === id ? '' : overlay;
    else { desktop[id] = open; remember('rea.ui.' + id, open ? 'open' : 'closed'); }
    renderPanels();
    if (!open && $(id).contains(active)) button(id).focus();
    else if (open && focus) $(id).querySelector('select:not(:disabled),button:not(:disabled),input:not(:disabled)')?.focus();
  }
  function togglePanel(id) { setPanel(id, button(id).getAttribute('aria-expanded') !== 'true', mobile.matches); }
  function closeOverlay() {
    const id = overlay;
    if (!id) return;
    setPanel(id, false); button(id).focus();
  }
  function viewChanged(view) {
    if (!mobile.matches || !overlay) return;
    const previous = overlay, active = document.activeElement;
    overlay = ''; renderPanels();
    if ($(previous).contains(active)) document.querySelector(`[data-view="${view}"]`)?.focus();
  }
  function reveal(value, {focus = false, scroll = true} = {}) {
    const target = typeof value === 'string' ? $(value) : value;
    if (!target) return false;
    const view = target.closest('.view');
    if (view?.hidden) showView(view.id.replace('view-', ''));
    if (target.closest('.composer') && document.querySelector('.workbench').classList.contains('analysis-active')) showView('overview');
    const panel = panels.find(id => $(id).contains(target));
    if (panel) setPanel(panel, true);
    else if (mobile.matches && overlay && focus && target.closest('.workbench')) { overlay = ''; renderPanels(); }
    if (target.tagName === 'DETAILS') target.open = true;
    for (let parent = target.parentElement?.closest('details'); parent; parent = parent.parentElement?.closest('details')) parent.open = true;
    // Source gating and disabled operations remain controlled by the actual application state.
    if (target.closest('[hidden]')) return false;
    if (scroll) target.scrollIntoView({block:'nearest', behavior:'auto'});
    if (focus) {
      const node = target.tagName === 'DETAILS' ? target.querySelector('summary') : target;
      if (node && !node.disabled) {
        if (!/^(BUTTON|INPUT|SELECT|TEXTAREA|SUMMARY|A)$/.test(node.tagName)) node.tabIndex = -1;
        node.focus({preventScroll:true});
      }
    }
    return true;
  }
  function updateTaskContext() {
    const model = $('model'), label = model.value ? model.selectedOptions[0]?.textContent : 'Choose a model';
    const mode = $('mode').value === 'code' ? 'Edit & run' : 'Read only';
    const text = (label || 'Choose a model') + ' · ' + mode;
    if ($('task-context').textContent !== text) $('task-context').textContent = text;
    $('task-context').title = text + ' — open task settings';
  }
  function setExpert(open) {
    expert = open; remember('rea.ui.expert', String(open));
    $('analysis-expert-toggle').setAttribute('aria-pressed', String(open));
    $('analysis-expert-toggle').setAttribute('aria-controls', 'rea-advanced');
    $('rea-advanced').open = open;
  }
  for (const id of panels) button(id).addEventListener('click', () => togglePanel(id));
  $('panel-backdrop').addEventListener('click', closeOverlay);
  $('task-context').addEventListener('click', () => { setPanel('settings', true); reveal('model', {focus:true}); });
  $('analysis-expert-toggle').addEventListener('click', () => setExpert(!expert));
  $('rea-advanced').addEventListener('toggle', () => {
    expert = $('rea-advanced').open;
    $('analysis-expert-toggle').setAttribute('aria-pressed', String(expert));
    remember('rea.ui.expert', String(expert));
  });
  for (const link of document.querySelectorAll('[data-analysis-section]')) link.addEventListener('click', () => reveal(link.dataset.analysisSection, {focus:true}));
  for (const id of ['model','mode']) $(id).addEventListener('change', updateTaskContext);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && mobile.matches && overlay && !document.querySelector('dialog[open]')) {
      event.preventDefault(); closeOverlay();
    }
  });
  mobile.addEventListener('change', () => {
    const active = document.activeElement;
    overlay = ''; renderPanels();
    const hidden = panels.find(id => $(id).inert && $(id).contains(active));
    if (hidden) button(hidden).focus();
  });
  // A modal owns focus while open; otherwise keep mobile panel focus within its controls and toggle.
  document.addEventListener('keydown', event => {
    if (event.key !== 'Tab' || !mobile.matches || !overlay || document.querySelector('dialog[open]')) return;
    const controls = [button(overlay), ...$(overlay).querySelectorAll('button,input,select,textarea,a[href],summary,[tabindex="0"]')]
      .filter(node => !node.disabled && node.getClientRects().length && !node.closest('[hidden],[inert]'));
    if (!controls.length) return;
    event.preventDefault();
    const current = controls.indexOf(document.activeElement);
    const next = current < 0 ? (event.shiftKey ? controls.length - 1 : 0)
      : (current + (event.shiftKey ? -1 : 1) + controls.length) % controls.length;
    controls[next].focus();
  });
  window.QuixiWorkflow = {reveal, togglePanel, updateTaskContext, viewChanged};
  renderPanels(); setExpert(expert); updateTaskContext();
})();
