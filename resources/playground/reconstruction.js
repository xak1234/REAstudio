/* Shared by the native UI and contract checks. No target code is executed here. */
'use strict';
const QuixiReconstruction = (() => {
  const pathKey = path => String(path || '').replace(/^\\\\\?\\/, '').replaceAll('\\', '/').replace(/\/+$/, '').toLowerCase();
  function separateProject(target, project, targetIsDirectory = false) {
    const a = pathKey(target), b = pathKey(project);
    const originalFolder = targetIsDirectory ? a : a.slice(0, a.lastIndexOf('/'));
    return !!a && !!b && !!originalFolder && a !== b && b !== originalFolder && !a.startsWith(b + '/') && !b.startsWith(originalFolder + '/');
  }
  function failure(record, value) {
    if (!record.failed) return null;
    const problem = value?.error || value?.result?.error;
    const issues = (problem?.details?.issues || []).map(i => i.message).filter(Boolean);
    const text = issues.join('\n') || problem?.message || record.response?.content?.filter(c => c.type === 'text').map(c => c.text).join('\n') || 'The analysis did not complete.';
    const resourceRange = record.tool === 'inspect_pe_resources' && /Resource range is not entirely file-backed in one section/i.test(text);
    return {
      message: text,
      guidance: resourceRange
        ? 'Some resource bytes are not stored in a file-backed section. This can occur with packed or runtime-populated resources. Changing the path or repeating this request will not recover those bytes. Continue with native code and import analysis; keep resource recovery marked incomplete.'
        : problem?.remediation?.action || 'Check the live input schema and the reported limitation before retrying.',
      nextTool: resourceRange ? 'open_binary' : null
    };
  }
  function marker(target) { return `Target: ${JSON.stringify(target)}\n`; }
  function plans(runs, project, target) {
    return runs.filter(r => r.project === project && r.mode === 'ask' && r.rea_enabled && r.status === 'completed' && r.reply?.trim() && r.prompt.startsWith('[Reconstruction brief]\n') && r.prompt.includes(marker(target)));
  }
  function prompt({ phase, target, targetIsDirectory = false, project, scope, goal, observations, plan, dossier, reportPath, recordIds = [] }) {
    if (!target) throw new Error('Select the application or feature artifact first.');
    if (!project) throw new Error('Open a separate destination project first.');
    if (!separateProject(target, project, targetIsDirectory)) throw new Error('Choose a destination project outside the original application folder, with no original artifact inside it.');
    goal = goal.trim();
    if (phase === 'plan' && scope === 'feature' && !goal) throw new Error('Describe the feature you want to rebuild.');
    if (phase === 'build' && !plan && !dossier) throw new Error('Complete an analysis brief for this artifact, then select it here.');
    const common = `${marker(target)}Destination project: ${JSON.stringify(project)}\nScope: ${scope === 'application' ? 'Whole application, delivered in stages' : 'Selected feature'}\nGoal: ${goal || 'Map the application and propose a staged functional rebuild.'}\nUser-supplied behaviour observations (unverified until tested):\n${observations.trim() || 'None supplied. Identify the missing observations.'}\n`;
    if (phase === 'build' || phase === 'retry') {
      const spec=dossier?`${dossier}/SPEC.md`:'SPEC.md',oracles=dossier?`${dossier}/oracle-cases.json`:'oracle-cases.json';
      return `[Reconstruction ${phase === 'retry'?'retry':'implementation'}]\nDestination project: ${JSON.stringify(project)}\nRead ${JSON.stringify(spec)} and this project's instructions. ${reportPath?`Read the actual oracle failure report ${JSON.stringify(reportPath)} and fix the failing requirements.`:'Implement the first bounded, testable milestone from the specification.'}\nUse SPEC.md, explicit expected outputs and project code as the implementation contract. Read only files needed for this milestone; do not repeat successful reads or enumerate analysis files. Do not read the original application, decompiled code or raw analysis evidence in this implementation run. If the specification is insufficient, record the exact gap for a separate REA analysis pass. Preserve unrelated work. Write new implementation code; never substitute a mock or claim unverified equivalence. Keep stable requirement IDs and remaining unknowns in SPEC.md. Fill ${JSON.stringify(oracles)} only with expected results supported by the specification or supplied observations, preserving expectationSource; do not adjust expected results merely to make the rebuild pass. The oracle file schema is {"version":1,"cases":[{"id":"unique-case-id","requirement":"REQ-001","command":"<PowerShell command>","expectationSource":"<SPEC requirement or observation>","expected":{"exitCode":0,"stdout":"<exact output>","stderr":""}}]}. Replace placeholders with supported cases; output matching includes whitespace and newlines. Use at most 12 cases per batch. Use the oracle action with config ${JSON.stringify(oracles)} to run actual comparisons. Inspect failures, fix the implementation and rerun, up to three repair attempts in this task. Stop and report a blocked requirement if needed. An empty suite is unverified. Report actual checks, unresolved differences and remaining milestones; passing selected cases does not establish whole-application equivalence.`;
    }
    return `[Reconstruction brief]\n${common}\nGather enough evidence to specify a functional rebuild. Read the relevant bundled guide with rea_workflow, path references/native-and-artifacts.md, references/android-applications.md or references/javascript-applications.md; page as needed. Use rea_tools for each canonical input schema and binary_session for availability. The toolchain action reports actual configured paths, not verified readiness. Inspect saved records first when relevant: ${recordIds.slice(0, 16).join(', ') || 'none'}. Failed records are limitations, not evidence of recovered behaviour.\nUse the minimum evidence needed for the requested feature. Do not enumerate every candidate schema: retrieve only a schema you intend to call next. Once saved evidence and supplied requirements cover this milestone, return the brief and list remaining unknowns. Choose available static tools appropriate to the artifact. Native PE candidates: inspect_pe_imports, inspect_native_exports, inspect_pe_resources, open_binary with the selected provider, binary_overview when available, list_procedures, search_strings or trace_feature, analyze_function, procedure_pseudo_code and get_call_graph. For .NET: inspect_managed_artifact, inspect_managed_members and inspect_managed_native_boundaries. For APK: inspect_android_package and its class/method/reference tools when JADX is configured. For JavaScript: analyze_javascript_application and trace_application_feature with its returned graph/evidence. Use only advertised names and arguments. Preserve record/Evidence IDs and exact locations in evidence. Page retained evidence with inspect_analysis_view. Never retry unchanged non-retryable errors. Do not execute the original application.\nReturn a functional SPEC.md draft with stable requirement IDs such as REQ-001: (1) target identity and coverage; (2) feature and UI-flow inventory; (3) inputs, outputs, state transitions, file/data formats and errors; (4) dependencies and platform boundaries tied to evidence references; (5) a table separating static facts, user observations, inference and unknowns; (6) architecture and bounded milestones; (7) oracle cases with requirement ID, inputs, expected outputs and expectation source only where supported, plus missing runtime/UI observations. Describe behaviour and interfaces, not copied decompiled implementation bodies. Prioritise the requested feature within the tool budget. Static analysis cannot prove runtime equivalence or recover absent servers/data/source. Ask mode returns the draft; Save SPEC creates its files for a separate implementation run.`;
  }
  return { separateProject, failure, plans, prompt };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = QuixiReconstruction;
