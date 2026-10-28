// Contract checks for real task handoff and parser-error guidance; no MCP results are simulated.
const assert = require('node:assert/strict');
const { separateProject, failure, plans, prompt } = require('../resources/playground/reconstruction.js');
assert.equal(separateProject('C:\\Original\\app.exe', '\\\\?\\c:\\original'), false);
assert.equal(separateProject('C:\\Original', 'C:\\Original\\rebuild', true), false);
assert.equal(separateProject('C:\\Original\\app.exe', 'C:\\Original\\rebuild'), false);
assert.equal(separateProject('C:\\Original\\app.exe', 'C:\\Rebuild'), true);
assert.equal(separateProject('C:\\Original', 'C:\\Original-two', true), true);
const problem = failure({failed:true,tool:'inspect_pe_resources'}, {error:{details:{issues:[{message:'Resource range is not entirely file-backed in one section.'}]}}});
assert.equal(problem.nextTool, 'open_binary');
assert.match(problem.guidance, /incomplete/);
assert.equal(failure({failed:false}, {}), null);
const input = {target:'C:\\Original\\app.exe',project:'C:\\Rebuild',scope:'feature',goal:'File validation',observations:'Empty input shows an error.',recordIds:['record-1']};
assert.throws(() => prompt({...input,project:'C:\\Original'}), /destination project outside/);
assert.throws(() => prompt({...input,phase:'build'}), /Complete an analysis brief/);
const brief = {id:'brief-1',project:'project-1',mode:'ask',rea_enabled:true,status:'completed',reply:'REQ-001: specified behaviour',prompt:prompt({...input,phase:'plan'})};
assert.deepEqual(plans([brief], 'project-1', input.target), [brief]);
assert.deepEqual(plans([brief], 'project-2', input.target), []);
assert.deepEqual(plans([{...brief,status:'failed'}], 'project-1', input.target), []);
assert.deepEqual(plans([{...brief,reply:'  '}], 'project-1', input.target), []);
assert.deepEqual(plans([brief], 'project-1', 'C:\\Original\\different.exe'), []);
assert.match(prompt({...input,phase:'build',plan:brief,dossier:'quixi-reconstruction-example'}), /quixi-reconstruction-example\/SPEC.md/);
assert.match(prompt({...input,phase:'retry',dossier:'quixi-reconstruction-example',reportPath:'quixi-oracle-runs/failed.json'}), /actual oracle failure report/);
assert.match(brief.prompt, /Failed records are limitations/);
const build = prompt({...input,phase:'build',plan:brief,dossier:'quixi-reconstruction-example'});
assert.match(build, /Case schema:/);
assert.match(build, /expectationSource/);
// The implementation agent cannot rewrite the contract or approve its own oracle suite.
assert.match(build, /read-only in this run/);
assert.match(build, /only the user can approve an oracle suite/);
assert.doesNotMatch(build, /\bFill\b/);
// argv cases run programs directly; the schema in the prompt must parse.
const schema = JSON.parse(build.match(/Case schema: (\{.*?\}\]\})/)[1]);
assert.deepEqual(schema.cases[0].argv, ['build/rebuild.exe', '--flag']);
assert.ok('stdin' in schema.cases[0] && !('command' in schema.cases[0]));
console.log('Reconstruction checks passed: target separation, brief selection, evidence handoff, read-only oracle contract and PE-resource recovery guidance.');
