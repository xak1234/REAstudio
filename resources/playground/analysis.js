/* Helpers for the live REA catalog and retained native evidence. */
// @ts-check
'use strict';
/** @typedef {Record<string, any>} JsonObject */
const QuixiAnalysis = (() => {
  /** @param {JsonObject} tool @param {string} target @param {string} provider */
  function defaults(tool, target, provider) {
    const properties = tool.inputSchema?.properties || {};
    /** @type {JsonObject} */
    const args = {};
    for (const key of ['path', 'input_path']) if (properties[key] && target) args[key] = target;
    if (properties.provider_id && tool.name === 'open_binary' && provider) args.provider_id = provider;
    for (const key of tool.inputSchema?.required || []) {
      if (key in args) continue;
      const schema = properties[key] || {};
      args[key] = schema.default ?? schema.const ?? schema.enum?.[0] ??
        (schema.type === 'boolean' ? false : schema.type === 'object' ? {} : schema.type === 'array' ? [] :
          ['number', 'integer'].includes(schema.type) ? Math.max(schema.minimum ?? 0, 0) : '');
    }
    if (properties.detail?.enum?.includes('summary')) args.detail = 'summary';
    return args;
  }
  /** Basic form preflight only; REA remains the full canonical schema validator.
   * @param {JsonObject} tool @param {any} args @returns {string[]} */
  function issues(tool, args) {
    if (!args || typeof args !== 'object' || Array.isArray(args)) return ['Arguments must be a JSON object.'];
    const schema = tool.inputSchema || {}, properties = schema.properties || {};
    /** @type {string[]} */
    const errors = [];
    for (const key of schema.required || []) if (!(key in args)) errors.push(`${key}: a value is required.`);
    for (const [key, value] of Object.entries(args)) {
      const s = properties[key];
      if (!s) { if (schema.additionalProperties === false) errors.push(`${key}: not in this tool's input schema.`); continue; }
      if (s.type) {
        const types = Array.isArray(s.type) ? s.type : [s.type];
        const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
        if (!types.includes(actual) && !(types.includes('integer') && Number.isInteger(value))) {
          errors.push(`${key}: expected ${types.join(' or ')}.`); continue;
        }
      }
      if (typeof value === 'string') {
        if (['procedure', 'pattern'].includes(key) && !value.trim()) errors.push(`${key}: enter ${key === 'procedure' ? 'a function name or address, or choose a function from the results' : 'text to search for'}.`);
        else if (s.minLength !== undefined && [...value].length < s.minLength) errors.push(`${key}: needs at least ${s.minLength} characters.`);
        if (s.maxLength !== undefined && [...value].length > s.maxLength) errors.push(`${key}: exceeds ${s.maxLength} characters.`);
      }
      if (typeof value === 'number') {
        if (s.minimum !== undefined && value < s.minimum) errors.push(`${key}: minimum is ${s.minimum}.`);
        if (s.maximum !== undefined && value > s.maximum) errors.push(`${key}: maximum is ${s.maximum}.`);
      }
      if (s.enum && !s.enum.includes(value)) errors.push(`${key}: choose ${s.enum.join(', ')}.`);
    }
    return errors;
  }
  /** @param {JsonObject} value */
  function nativeView(value) {
    const result = value?.normalized_result;
    if (!result || !['list_procedures', 'search_procedures', 'list_strings', 'search_strings', 'list_names'].includes(result.parent_operation)) return null;
    if (!['summary', 'native-inventory'].includes(result.kind) || typeof result.parent_evidence_id !== 'string') return null;
    return result;
  }
  /** @param {JsonObject} view @param {number} offset @param {number} [limit] */
  function pageArguments(view, offset, limit = 50) {
    if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('Invalid evidence page.');
    return {source: {kind: 'retained-evidence', evidence_id: view.parent_evidence_id}, view: {kind: 'native-inventory', offset, limit}};
  }
  /** @param {JsonObject} row @returns {string|null} */
  function procedure(row) {
    const r = row.record;
    if (!r || r.procedure?.external || r.symbol?.external) return null;
    return typeof r.address === 'string' && r.address.trim() ? r.address : typeof r.value === 'string' && r.value.trim() ? r.value : null;
  }
  /** @param {string} a @param {string} b */
  function sameTarget(a, b) {
    /** @param {string} s */
    const key = s => String(s || '').replace(/^\\\\\?\\/, '').replaceAll('\\', '/').replace(/\/+$/, '').toLowerCase();
    return !!a && !!b && key(a) === key(b);
  }
  // Bidi overrides, zero-width/format characters and C0/C1 controls become visible escapes.
  const HIDDEN = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2028\u2029\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB\u{E0000}-\u{E007F}]/gu;
  /** @param {any} value @param {boolean} [code] Keep tabs and line breaks in multi-line code. */
  function visible(value, code = false) {
    return String(value ?? '').replace(HIDDEN, c => {
      if (code && (c === '\t' || c === '\n' || c === '\r')) return c;
      if (c === '\t') return '\\t'; if (c === '\n') return '\\n'; if (c === '\r') return '\\r';
      const n = /** @type {number} */ (c.codePointAt(0));
      return n > 0xffff ? `\\u{${n.toString(16).toUpperCase()}}` : `\\u${n.toString(16).toUpperCase().padStart(4, '0')}`;
    });
  }
  const cWords = new Set('if else while for do switch case default break continue return goto sizeof typedef struct union enum static extern const volatile register inline __fastcall __stdcall __cdecl __thiscall'.split(' '));
  const cTypes = new Set('void char short int long float double signed unsigned bool _Bool wchar_t size_t code byte word dword qword uint ulong ushort uchar longlong ulonglong undefined undefined1 undefined2 undefined4 undefined8 int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t __int8 __int16 __int32 __int64 BOOL BYTE WORD DWORD QWORD HANDLE LPVOID LPCSTR LPSTR LPCWSTR LPWSTR'.split(' '));
  const cLexer = /(\/\*[\s\S]*?(?:\*\/|(?![\s\S])))|(\/\/[^\n]*)|("(?:\\.|[^"\\\n])*"?|'(?:\\.|[^'\\\n])*'?)|(^[ \t]*#[^\n]*)|(0[xX][0-9a-fA-F]+[uUlL]*|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[uUlLfF]*)|([A-Za-z_][\w]*)|(\s+)|([\s\S])/my;
  /** Lightweight C tokens; every token is plain text and the texts concatenate to the input.
   * @param {string} source @returns {{type:string,text:string}[]} */
  function cTokens(source) {
    const text = String(source ?? ''), tokens = [];
    const kinds = ['comment', 'comment', 'string', 'preproc', 'number', 'ident', 'plain', 'plain'];
    cLexer.lastIndex = 0;
    while (cLexer.lastIndex < text.length) {
      const m = cLexer.exec(text); if (!m) break;
      const i = m.slice(1).findIndex(g => g !== undefined);
      let type = kinds[i]; if (type === 'ident') type = cWords.has(m[0]) ? 'keyword' : cTypes.has(m[0]) ? 'type' : 'ident';
      const last = tokens[tokens.length - 1];
      if (type === 'plain' && last?.type === 'plain') last.text += m[0]; else tokens.push({type, text: m[0]});
    }
    return tokens;
  }
  /** @param {string} value @param {boolean} [loose] Accept bare hexadecimal. @returns {string|null} */
  function address(value, loose = false) {
    const m = String(value ?? '').trim().replace(/^(ram|mem|code):/i, '').match(loose ? /^(?:0x)?([0-9a-f]+)h?$/i : /^0x([0-9a-f]+)$/i);
    return m ? `0x${m[1].replace(/^0+(?=.)/, '').toLowerCase()}` : null;
  }
  /** @param {JsonObject} root @param {JsonObject} s */
  function deref(root, s) {
    for (let n = 0; s?.$ref && n < 8; n++) {
      const {$ref, ...rest} = s, next = (root.$defs || root.definitions || {})[String($ref).replace(/^#\/(\$defs|definitions)\//, '')];
      if (!next) break; s = {...next, ...rest};
    }
    return s || {};
  }
  /** @param {JsonObject} s */
  const typeOf = s => (Array.isArray(s.type) ? s.type.find(/** @param {string} t */ t => t !== 'null') : s.type) || (s.items ? 'array' : s.properties ? 'object' : '');
  /** @type {Record<string,string[]>} */
  const intentFields = {address: ['procedure', 'address', 'addr', 'addrs', 'ea', 'start_address', 'procedure_address', 'function', 'func', 'queries', 'query'], name: ['name', 'new_name', 'newName'], comment: ['comment', 'cmt', 'text']};
  /** Map intents (address, name, comment) onto a live schema's own field names.
   * @param {JsonObject} schema @param {Record<string,string>} intents @param {JsonObject} [root] @returns {JsonObject} */
  function fillArgs(schema, intents, root = schema || {}) {
    const props = deref(root, schema || {}).properties || {}, out = /** @type {JsonObject} */ ({});
    for (const [intent, value] of Object.entries(intents)) {
      if (value === undefined || value === null || value === '') continue;
      const scalar = /** @param {string} k */ k => { const s = deref(root, props[k]), t = typeOf(s); return t !== 'object' && !(t === 'array' && typeOf(deref(root, s.items || {})) === 'object'); };
      const field = (intentFields[intent] || [intent]).find(k => k in props && !(k in out) && scalar(k)); if (!field) continue;
      out[field] = typeOf(deref(root, props[field])) === 'array' ? [value] : value;
    }
    if (Object.keys(out).length) return out;
    const fields = Object.keys(props).sort((a, b) => Number(/^func/i.test(b)) - Number(/^func/i.test(a)));
    for (const field of fields) {
      const s = deref(root, props[field]), t = typeOf(s);
      const item = t === 'object' ? s : t === 'array' && typeOf(deref(root, s.items || {})) === 'object' ? deref(root, s.items) : null;
      if (!item) continue;
      const inner = fillArgs(item, intents, root);
      if (Object.keys(inner).length) { out[field] = t === 'array' ? [inner] : inner; break; }
    }
    return out;
  }
  /** Successful original function evidence (never a model suggestion or unsaved view). @param {JsonObject} record */
  function functionRecord(record) {
    return !!record && !record.failed && !record.transient && record.kind !== 'model-suggestion' &&
      /pseudo|assembly|decompil|disasm|function_instructions|analyze_function/.test(String(record.tool || ''));
  }
  /** Newest first, optionally limited to one target and one tool.
   * @param {JsonObject[]} records @param {{target?:string,tool?:string}} [filter] */
  function filterHistory(records, {target = '', tool = ''} = {}) {
    const time = /** @param {JsonObject} r */ r => Date.parse(r.created) || 0;
    return (records || []).filter(r => (!target || sameTarget(r.target, target)) && (!tool || r.tool === tool)).sort((a, b) => time(b) - time(a));
  }
  /** @param {JsonObject[]} records */
  function historyFacets(records) {
    /** @type {string[]} */ const targets = [];
    for (const r of records || []) if (r.target && !targets.some(t => sameTarget(t, r.target))) targets.push(r.target);
    return {targets, tools: [...new Set((records || []).map(r => r.tool).filter(t => typeof t === 'string' && t))].sort()};
  }
  /** Ignore responses overtaken by a newer request. */
  function sequencer() { let n = 0; return {next: () => ++n, current: /** @param {number} t */ t => t === n}; }
  /** @param {string} a */
  const quoteArg = a => !a || /[\s"']/.test(a) ? `"${a.replaceAll('"', '\\"')}"` : a;
  /** Display model for oracle consent; every value is escaped text, never markup.
   * @param {JsonObject} preview */
  function oraclePlan(preview) {
    const sha256 = String(preview?.sha256 || '');
    const cases = (Array.isArray(preview?.cases) ? preview.cases : []).map(/** @param {JsonObject} c @param {number} i */ (c, i) => {
      const argv = typeof c?.command !== 'string' && Array.isArray(c?.argv);
      const command = argv ? c.argv.map(/** @param {any} a */ a => quoteArg(String(a))).join(' ') : typeof c?.command === 'string' ? c.command : '';
      const expectations = [];
      const expected = c?.expected || c;
      if (expected?.exitCode !== undefined && expected.exitCode !== null) expectations.push(`exit code ${expected.exitCode}`);
      for (const k of ['stdout', 'stderr']) if (expected?.[k] !== undefined && expected[k] !== null) expectations.push(`${k}: ${typeof expected[k] === 'string' ? expected[k] : JSON.stringify(expected[k])}`);
      if (c?.timeoutSeconds) expectations.push(`timeout: ${c.timeoutSeconds} seconds`);
      for (const file of Array.isArray(expected?.files) ? expected.files : []) {
        expectations.push(`file ${file.path}: ${file.exists === false ? 'must be absent' : 'must exist'}`);
        if (file.sha256) expectations.push(`  SHA-256: ${file.sha256}`);
        if (file.text !== undefined && file.text !== null) expectations.push(`  exact text: ${file.text}`);
        if (Object.prototype.hasOwnProperty.call(file, 'json')) expectations.push(`  JSON value: ${JSON.stringify(file.json)}`);
      }
      return {name: visible(c?.name || `Case ${i + 1}`), form: argv ? 'argv' : 'command', command: visible(command, true), missing: !command.trim(), expectations: expectations.map(e => visible(e, true))};
    });
    const valid = /^[a-f0-9]{64}$/i.test(sha256), approvedSha256 = preview?.approvedSha256 ?? null;
    return {config: visible(preview?.config || ''), sha256, valid, cases, empty: !cases.length,
      approved: valid && preview?.approved === true && (approvedSha256 === null || approvedSha256 === sha256),
      changed: typeof approvedSha256 === 'string' && approvedSha256 !== sha256};
  }
  /** @param {number} n */
  const formatSize = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
  /** Pretty-print small results only; large ones stay compact and are capped for display.
   * @param {string} compact @param {number} [prettyLimit] @param {number} [maxChars] */
  function rawText(compact, prettyLimit = 1000000, maxChars = 4000000) {
    const pretty = compact.length <= prettyLimit;
    const text = pretty ? JSON.stringify(JSON.parse(compact), null, 2) : compact;
    return {text: text.length > maxChars ? text.slice(0, maxChars) : text, pretty, truncated: text.length > maxChars, size: compact.length};
  }
  /** @param {JsonObject} row @param {string} query */
  function rowMatches(row, query) {
    const q = String(query || '').trim().toLowerCase(); if (!q) return true;
    const r = row?.record || {};
    return [r.address, typeof r.value === 'string' ? r.value : JSON.stringify(r.value ?? '')].some(v => String(v ?? '').toLowerCase().includes(q));
  }
  // ---- Models: connections supply models; the Agent model runs every task and calls tools, one of which is the optional Decompile helper. ----
  /** @param {string} m @param {string} w */
  const hasWord = (m, w) => new RegExp(`(^|[^a-z])${w}([^a-z]|$)`).test(m);
  /** LLM4Decompile input type from the model id. Explicit "ref"/"end" words win; upstream V2 releases are Ref and V1.5 releases are End; otherwise Ref.
   * @param {string} model @returns {{profile:'llm4-ref'|'llm4-end', reason:string}} */
  function helperProfile(model) {
    const m = String(model || '').toLowerCase();
    if (hasWord(m, 'ref')) return {profile: 'llm4-ref', reason: 'the model name contains “ref”'};
    if (hasWord(m, 'end')) return {profile: 'llm4-end', reason: 'the model name contains “end”'};
    if (/v1\.5/.test(m)) return {profile: 'llm4-end', reason: 'LLM4Decompile V1.5 releases are End models'};
    if (/v2/.test(m)) return {profile: 'llm4-ref', reason: 'LLM4Decompile V2 releases are Ref models'};
    return {profile: 'llm4-ref', reason: 'default'};
  }
  /** One-line Decompile helper state from decompile/status and the provider list (never invented).
   * @param {JsonObject|null} status @param {JsonObject[]} [providers] */
  function helperStatus(status, providers = []) {
    if (!status) return {state: 'unknown', text: 'Checking…'};
    const s = status.settings || {}, model = String(s.model || '').trim();
    const conn = (providers || []).find(p => p.id === s.provider && p.configured), via = conn ? ` via ${conn.name || conn.id}` : '';
    if (!s.enabled) return {state: 'off', text: model ? `Off · ${model}${via} saved` : 'Off · Set up'};
    if (!model) return {state: 'needs-model', text: 'Needs a model'};
    if (!conn) return {state: 'needs-connection', text: 'Needs a connection'};
    return status.connected ? {state: 'ready', text: `On · ${model}${via} · last request succeeded`} : {state: 'on', text: `On · ${model}${via}`};
  }
  /** Connection row status from saved provider state and its last test only. @param {JsonObject} p */
  function connectionStatus(p) {
    const ms = typeof p?.lastLatencyMs === 'number' ? ` · ${p.lastLatencyMs} ms` : '';
    const text = p?.lastTestedOk === true ? `Last test passed${ms}` : p?.lastTestedOk === false ? 'Last test failed' : 'Not tested';
    const key = p?.credentialSource === 'saved' ? 'saved key' : p?.credentialSource === 'environment' ? `key from ${p.environmentVariable || 'environment'}` : p?.credentialSource === 'oauth' ? 'signed in' : 'no key';
    const count = (p?.models || []).length;
    return {ok: p?.lastTestedOk ?? null, text, detail: [p?.baseUrl || 'no base URL', key, `${count} model${count === 1 ? '' : 's'}`].join(' · ')};
  }
  /** Function text kind a record offers the helper: 'pseudocode', 'assembly' or '' (unknown; the engine decides). @param {JsonObject} record */
  function helperInputKind(record) {
    if (!functionRecord(record)) return '';
    const t = String(record.tool || '');
    return /pseudo|decompil/.test(t) ? 'pseudocode' : /assembly|disasm|function_instructions/.test(t) ? 'assembly' : '';
  }
  /** Why a record cannot feed the helper's input type, or ''. REA and IDA bridge records both qualify. @param {JsonObject} record @param {string} profile */
  function helperInputIssue(record, profile) {
    if (!functionRecord(record)) return 'Select a successful original function record (decompiled pseudocode or assembly, from REA/Ghidra or the IDA bridge) first.';
    const kind = helperInputKind(record), want = profile === 'llm4-end' ? 'assembly' : 'pseudocode';
    return kind && kind !== want ? `This record holds ${kind}, but the helper model takes ${want} (${profile}). Select a ${want} record, or change Model input in helper setup → Advanced.` : '';
  }
  // ---- Coding workspace: editor, terminal, runs and Git changes. Pure; app.js renders every value with textContent. ----
  /** The editor textarea is LF-only; compare and edit LF-normalised text. @param {any} text */
  const normalizeEol = text => String(text ?? '').replace(/\r\n?/g, '\n');
  /** "CRLF · UTF-8 (BOM)" from read's lineEnding/bom; builds without them are treated as LF.
   * The editor is LF-only, so a mixed file is saved with LF line endings. @param {JsonObject|null} file */
  function fileFormat(file) {
    const eol = /** @type {Record<string,string>} */ ({crlf: 'CRLF', lf: 'LF', mixed: 'Mixed line endings — saving will normalise to LF'})[String(file?.lineEnding || '')] || 'LF';
    return `${eol} · UTF-8${file?.bom ? ' (BOM)' : ''}`;
  }
  /** What the Tab key inserts: a real tab for Makefiles, *.mk, *.go, *.tsv and files already indented with tabs, else 4 spaces.
   * @param {string} path @param {string} content */
  function indentUnit(path, content) {
    const name = String(path || '').replaceAll('\\', '/').split('/').pop()?.toLowerCase() || '';
    if (/^(gnu)?makefile$|\.(mk|go|tsv)$/.test(name)) return '\t';
    let tabs = 0, spaces = 0;
    for (const line of String(content || '').split('\n', 5000)) { if (line[0] === '\t') tabs++; else if (line.startsWith('  ')) spaces++; }
    return tabs > spaces ? '\t' : '    ';
  }
  /** Line diff (LCS) between two texts after trimming the shared head and tail; null when too large to compare here.
   * @param {string} before @param {string} after @param {number} [maxCells] */
  function lineDiff(before, after, maxCells = 4000000) {
    const a = normalizeEol(before).split('\n'), b = normalizeEol(after).split('\n');
    let head = 0; while (head < a.length && head < b.length && a[head] === b[head]) head++;
    let ea = a.length, eb = b.length; while (ea > head && eb > head && a[ea - 1] === b[eb - 1]) { ea--; eb--; }
    const x = a.slice(head, ea), y = b.slice(head, eb);
    if (x.length * y.length > maxCells) return null;
    const t = Array.from({length: x.length + 1}, () => new Uint32Array(y.length + 1));
    for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) t[i][j] = x[i] === y[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
    /** @type {{cls:string,text:string}[]} */ const out = [];
    if (head) out.push({cls: 'hunk', text: `@@ ${head} unchanged line${head === 1 ? '' : 's'} @@`});
    let i = 0, j = 0;
    while (i < x.length || j < y.length) {
      if (i < x.length && j < y.length && x[i] === y[j]) { out.push({cls: '', text: ` ${x[i]}`}); i++; j++; }
      else if (j < y.length && (i >= x.length || t[i][j + 1] > t[i + 1][j])) out.push({cls: 'added', text: `+${y[j++]}`});
      else out.push({cls: 'removed', text: `-${x[i++]}`});
    }
    const tail = a.length - ea;
    if (tail) out.push({cls: 'hunk', text: `@@ ${tail} unchanged line${tail === 1 ? '' : 's'} @@`});
    return out;
  }
  /** One page of a unified diff with the existing line classes; large diffs are paged instead of rendered at once.
   * @param {string} diff @param {number} [offset] @param {number} [limit] */
  function diffLines(diff, offset = 0, limit = 5000) {
    const lines = String(diff || '').split('\n'), end = Math.min(lines.length, offset + limit);
    return {lines: lines.slice(offset, end).map(l => ({text: l, cls: l.startsWith('+') ? 'added' : l.startsWith('-') ? 'removed' : l.startsWith('@@') ? 'hunk' : ''})),
      total: lines.length, next: end < lines.length ? end : null};
  }
  /** Streamed terminal output: adjacent chunks of one stream merge. @param {{stream:string,text:string}[]} parts @param {JsonObject[]} chunks */
  function appendChunks(parts, chunks) {
    const out = (parts || []).map(p => ({...p}));
    for (const c of chunks || []) {
      const stream = c?.stream === 'stderr' ? 'stderr' : 'stdout', text = typeof c?.text === 'string' ? c.text : '';
      if (!text) continue;
      const last = out[out.length - 1];
      if (last?.stream === stream) last.text += text; else out.push({stream, text});
    }
    return out;
  }
  /** Command history with the newest last; repeats of the last command are not added. @param {string[]} history @param {string} command @param {number} [cap] */
  function rememberCommand(history, command, cap = 200) {
    const list = (history || []).filter(h => typeof h === 'string');
    if (command && list[list.length - 1] !== command) list.push(command);
    return list.slice(-cap);
  }
  /** Up (-1) / Down (+1) recall; index === history.length is the unsent draft. @param {string[]} history @param {number} index @param {number} step @param {string} draft */
  function recallCommand(history, index, step, draft = '') {
    const next = Math.max(0, Math.min(history.length, index + step));
    return {index: next, value: next === history.length ? draft : history[next]};
  }
  const activeRunStatuses = ['running', 'stopping', 'awaiting_approval'];
  /** @param {any} v */
  const timeOf = v => typeof v === 'number' ? v : typeof v === 'string' ? Date.parse(v) : NaN;
  /** @param {number} ms */
  function duration(ms) {
    const s = Math.round(ms / 1000);
    return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s` : `${Math.floor(s / 3600)}h ${String(Math.floor(s / 60) % 60).padStart(2, '0')}m`;
  }
  /** Provider/model, mode, elapsed time and step count when the run reports them. @param {JsonObject} run @param {number} [now] */
  function runMeta(run, now = Date.now()) {
    // The engine reports startedAt/finishedAt (epoch milliseconds); the other names are fallbacks.
    const start = timeOf(run?.startedAt ?? run?.started ?? run?.created),
      end = timeOf(run?.finishedAt ?? run?.finished ?? run?.ended ?? run?.completed ?? (activeRunStatuses.includes(run?.status) ? now : run?.updated));
    const steps = run?.steps ?? run?.stepCount;
    return [run?.provider && run?.model ? `${run.provider} / ${run.model}` : run?.model, run?.mode, Number.isFinite(start) && Number.isFinite(end) && end >= start ? duration(end - start) : '',
      typeof steps === 'number' ? `${steps} step${steps === 1 ? '' : 's'}` : '', run?.rea_enabled ? 'REA enabled' : ''].filter(Boolean).map(v => visible(String(v))).join(' · ');
  }
  /** Run history search over prompt, status and model. @param {JsonObject} run @param {string} query */
  function runMatches(run, query) {
    const q = String(query || '').trim().toLowerCase();
    return !q || [run?.prompt, run?.status, run?.model, run?.provider].some(v => String(v ?? '').toLowerCase().includes(q));
  }
  /** The command a run waits on, escaped for display. @param {any} pending */
  function pendingCommand(pending) {
    if (!pending) return {command: '', detail: ''};
    if (typeof pending === 'string') return {command: visible(pending, true), detail: ''};
    const command = pending.command ?? pending.cmd ?? (Array.isArray(pending.argv) ? pending.argv.join(' ') : JSON.stringify(pending));
    return {command: visible(String(command), true), detail: [pending.cwd && `Working directory: ${pending.cwd}`, pending.risk && `Risk: ${pending.risk}`, pending.reason && `Why approval is needed: ${pending.reason}`]
      .filter(Boolean).map(v => visible(String(v))).join('\n')};
  }
  /** Skipped run-revert entries that forcing can still revert (not already reverted or unchanged by the run).
   * @param {any} skipped @returns {JsonObject[]} */
  function forceableSkips(skipped) {
    return (Array.isArray(skipped) ? skipped : []).filter(s => s && !/^(Already reverted|This task did not change that file)/i.test(String(s.reason || '')));
  }
  /** Status letter and +/− counts for one changed file. @param {JsonObject} f */
  function gitFileLabel(f) {
    const s = String(f?.status || '').trim();
    const letter = s === '??' || /^untracked/i.test(s) ? 'U' : /^(added|new)/i.test(s) ? 'A' : /^del/i.test(s) ? 'D' : /^ren/i.test(s) ? 'R' : /^mod/i.test(s) ? 'M' : (s.replace(/[^A-Za-z]/g, '').charAt(0) || 'M').toUpperCase();
    const n = /** @param {any} v */ v => typeof v === 'number' && Number.isFinite(v) ? v : null;
    const add = n(f?.additions), del = n(f?.deletions);
    return {letter, counts: add === null && del === null ? (f?.binary ? 'binary' : '') : `+${add ?? 0} −${del ?? 0}`, staged: !!f?.staged};
  }
  // ---- Guided reverse-engineering workflow. Pure: app.js supplies a snapshot of real state only. ----
  /** @param {string} path @param {boolean} [isDirectory] @param {JsonObject} [hint] Detected from saved results. */
  function targetKind(path, isDirectory = false, hint = {}) {
    if (!path) return '';
    if (hint?.managed) return 'dotnet';
    const ext = (String(path).match(/\.([a-z0-9]+)$/i)?.[1] || '').toLowerCase();
    if (['apk', 'aab', 'xapk', 'apks'].includes(ext)) return 'apk';
    if (hint?.javascript || isDirectory || ['asar', 'js', 'mjs', 'cjs', 'html', 'htm'].includes(ext)) return 'javascript';
    if (['exe', 'dll', 'sys', 'ocx', 'cpl', 'scr', 'efi', 'drv', 'so', 'elf', 'dylib', 'bin', 'ko'].includes(ext)) return 'native';
    return 'other';
  }
  /** Kind hints from a successful result's text (format/metadata fields), never from file names.
   * @param {string} tool @param {boolean} failed @param {string} text */
  function kindHint(tool, failed, text) {
    if (failed) return {};
    const t = String(text || '');
    if (tool === 'inspect_managed_artifact' && /"(is_)?managed"\s*:\s*true|"clr[_a-z]*"\s*:\s*\{|cli_header|ECMA-335|\.NET (assembly|metadata)/i.test(t)) return {managed: true};
    if (tool === 'open_binary' && /"format"\s*:\s*"[^"]*(\.net|clr|managed)/i.test(t)) return {managed: true};
    if (tool === 'analyze_javascript_application') return {javascript: true};
    return {};
  }
  /** @type {Record<string,RegExp>} */
  const evidenceTools = {functions: /^(list_procedures|search_procedures|list_funcs|lookup_funcs)$/, decompiled: /^(procedure_pseudo_code|decompile|batch_decompile)$/,
    strings: /^(list_strings|search_strings|find_regex)$/, imports: /^(inspect_pe_imports|inspect_native_exports|inspect_native_api|imports)$/,
    managed: /^(inspect_managed_artifact|inspect_managed_members)$/, javascript: /^(analyze_javascript_application|trace_application_feature|recover_javascript_sources)$/,
    android: /^(inspect_android_package|search_android_classes|inspect_android_class)$/, annotated: /^(set_address_name|set_addresses_names|set_comment|set_inline_comment|rename|set_comments)$/};
  /** Successful saved records for this target only. @param {JsonObject[]} records @param {string} target */
  function evidenceSummary(records, target) {
    /** @type {Record<string,boolean>} */ const out = {};
    for (const k of Object.keys(evidenceTools)) out[k] = false;
    for (const r of records || []) if (!r.failed && target && sameTarget(r.target, target))
      for (const [k, re] of Object.entries(evidenceTools)) if (re.test(String(r.tool || ''))) out[k] = true;
    return out;
  }
  const guidanceField = /^(remediation|next|next_steps?|next_actions?|guidance|hints?|suggestions?|recommended_next_(tool|action)s?|recovery)$/i;
  /** The provider's own error and remediation text for a failed record, escaped for display.
   * @param {JsonObject} record @param {any} value Unwrapped response. */
  function failureInfo(record, value) {
    if (!record?.failed) return null;
    /** @type {string[]} */ const found = [];
    /** @param {any} v @param {number} depth */
    const walk = (v, depth) => {
      if (depth > 8 || !v || typeof v !== 'object') return;
      for (const [k, x] of Object.entries(v)) {
        if (guidanceField.test(k)) for (const item of [x].flat()) {
          const s = typeof item === 'string' ? item : item && typeof item === 'object' ? item.message || item.action || item.tool : '';
          if (typeof s === 'string' && s.trim()) found.push(s.trim());
        }
        if (x && typeof x === 'object') walk(x, depth + 1);
      }
    };
    walk(value, 0);
    const text = (record.response?.content || []).filter(/** @param {JsonObject} c */ c => c?.type === 'text').map(/** @param {JsonObject} c */ c => c.text).join('\n');
    const raw = value?.error?.message || (typeof value?.error === 'string' ? value.error : '') || (typeof value?.message === 'string' ? value.message : '') || text;
    const error = visible(String(raw || ''), true).trim();
    return {id: String(record.id || ''), tool: String(record.tool || ''), failed: true, error: error.length > 600 ? `${error.slice(0, 600)}…` : error,
      remediation: [...new Set(found)].slice(0, 4).map(s => visible(s, true))};
  }
  /** @param {JsonObject} s */
  function normal(s) {
    const o = s || {};
    return {project: !!o.project, model: !!o.model, connections: Number(o.connections) || 0, rea: {connected: !!o.rea?.connected, catalog: !!o.rea?.catalog, tools: o.rea?.tools || []},
      target: {path: o.target?.path || '', kind: o.target?.kind || targetKind(o.target?.path || '', o.target?.isDirectory)}, source: o.source || null,
      sources: o.sources || [], provider: o.provider || 'ghidra', opened: !!o.opened, evidence: {...evidenceSummary([], ''), ...(o.evidence || {})}, last: o.last || null,
      ida: {unsupported: false, installed: false, enabled: false, connected: false, session: false, allowAnnotations: false, reaUsesHeadless: false, registrationPath: '', registrationError: '', ...(o.ida || {})},
      debugger: {connected: false, sessionConnected: false, ...(o.debugger || {})}, specialist: {enabled: false, model: '', connection: true, ...(o.specialist || {})},
      reconstruction: {brief: false, dossier: '', oracleCases: null, approved: false, oracleStatus: '', ...(o.reconstruction || {})}, dismissed: o.dismissed || []};
  }
  /** @param {string} id @param {string} kind @param {string} title @param {string} why @param {string} target @param {JsonObject} [extra] */
  const step = (id, kind, title, why, target, extra = {}) => ({id, kind, title, why, target, ...extra});
  /** @param {ReturnType<typeof normal>} s */
  const idaRegistered = s => !!s.ida.reaUsesHeadless || !!s.ida.registrationPath && !s.ida.registrationError;
  /** @param {ReturnType<typeof normal>} s */
  const enoughEvidence = s => s.evidence.decompiled || s.evidence.javascript || s.evidence.managed || s.evidence.android;
  /** Why the selected analysis source cannot be used yet, or ''. @param {ReturnType<typeof normal>} s */
  function sourceIssue(s) {
    const id = s.source?.id || '';
    if ((id === 'ida' || s.provider === 'ida' && s.target.kind === 'native') && !(s.ida.connected && s.ida.session) && !idaRegistered(s)) return 'IDA is selected but neither REA’s IDA registration nor the IDA bridge is configured.';
    if (id === 'ida-headless' && !(s.ida.connected && s.ida.session)) return s.ida.enabled ? 'IDA bridge enabled · no database open.' : 'IDA bridge is disabled.';
    if (id === 'x64dbg' && !s.debugger.connected) return 'x64dbg bridge is disabled.';
    if (s.target.kind === 'apk' && !s.sources.includes('jadx-mcp')) return 'Android packages need the JADX MCP provider.';
    return '';
  }
  const connectStep = step('connect', 'required', 'Connect REA', 'Starts the bundled REA plugin and loads its live tool catalog and availability.', 'rea-connect');
  const targetStep = step('select-target', 'required', 'Select an artifact', 'Choose the EXE, DLL, package or application folder to analyse with File… or Folder….', 'artifact-file');
  /** Ordered rule table; earlier rules have higher priority. Each returns zero or more steps.
   * @type {((s: ReturnType<typeof normal>) => JsonObject[])[]} */
  const guideRules = [
    s => s.last?.failed ? [step(`fix-${s.last.id}`, 'required', `Resolve: ${s.last.tool} reported an error`,
      [s.last.error || 'Open Complete result to read the error.', ...s.last.remediation.map(/** @param {string} r */ r => `Provider guidance: ${r}`)].join('\n'), 'evidence-raw')] : [],
    s => s.last?.failed && s.last.tool === 'inspect_pe_resources' && /file-backed|incomplete/i.test(`${s.last.error} ${s.last.remediation.join(' ')}`) ?
      [step('fix-pe-resources', 'recommended', 'Continue with native analysis', 'The PE resource table is not entirely file-backed, so that view is incomplete. Open the native target and continue with functions, strings and imports (README troubleshooting).', 'rea-run', {tool: 'open_binary'})] : [],
    s => s.last?.failed && /containment|not contained|outside (the )?(allowed|workspace|root)|\bUNC\b|network (path|drive|share)|reparse|junction|symbolic link|onedrive/i.test(`${s.last.error} ${s.last.remediation.join(' ')}`) ?
      [step('fix-local-path', 'recommended', 'Use a fixed local NTFS path', 'Ghidra and REA need the artifact on a fixed local NTFS drive. Copy it to a local folder (for example C:\\Analysis\\app.exe) and select that copy.', 'artifact-set-path')] : [],
    s => s.rea.connected ? [] : [connectStep],
    s => s.target.path ? [] : [targetStep],
    s => {
      const id = s.source?.id || '';
      if ((id === 'ida' || s.provider === 'ida' && s.target.kind === 'native') && !(s.ida.connected && s.ida.session) && !idaRegistered(s))
        return s.ida.installed ? [step('configure-ida', 'config', 'Use IDA for REA (headless)', `REA’s IDA provider is not configured${s.ida.registrationError ? ` (${visible(s.ida.registrationError)})` : ''}. Use IDA for REA (headless) in the IDA Pro panel, then reconnect REA to apply it.`, 'ida-register-rea')] :
          [step('install-ida', 'config', 'Prepare IDA bridge setup', 'The IDA bridge is not installed. Prepare its setup command (requires your licensed IDA Pro), run it in Terminal, then use “Use IDA for REA (headless)” and reconnect REA.', 'ida-setup')];
      if (id === 'ida-headless' && !s.ida.enabled) return [step('enable-ida', 'config', 'Enable the IDA bridge', 'Enable headless IDA (or attach to an open IDA window) to use the live IDA tools.', 'ida-enable-headless')];
      if (id === 'ida-headless' && !s.ida.session) return [step('open-ida', 'required', 'Open the target in IDA', 'The IDA bridge is enabled but no database is open for the selected target.', 'ida-open')];
      if (id === 'x64dbg' && !s.debugger.connected) return [step('enable-debugger', 'config', 'Enable the x64dbg bridge', 'Use Prepare bridge setup if the bridge is not installed, then Enable connection. Starting a target runs its code under the debugger.', 'debugger-toggle')];
      if (id === 'x64dbg' && !s.debugger.sessionConnected) return [step('debugger-session', 'recommended', 'Start or attach a debugger session', 'Start the selected target under x64dbg, or connect an existing debugger session by PID.', 'debugger-start')];
      if (s.target.kind === 'apk' && !s.sources.includes('jadx-mcp')) return [step('configure-jadx', 'config', 'Configure JADX MCP', 'Android packages are analysed through the JADX MCP provider. Set it up in Toolchain, then reconnect REA.', 'toolchain-open', {action: 'toolchain'})];
      return [];
    },
    s => !s.specialist.enabled ? [] : !s.specialist.model ? [step('specialist-models', 'config', 'Choose a Decompile helper model', 'The Decompile helper is enabled but has no model. Open its setup, discover the models on its connection and pick one.', 'helper-setup', {action: 'helper'})] :
      !s.specialist.connection ? [step('specialist-connection', 'config', 'Choose a Decompile helper connection', 'The Decompile helper’s connection is no longer configured. Open its setup and choose a configured connection.', 'helper-setup', {action: 'helper'})] : [],
    s => exploreSteps(s),
    s => rebuildSteps(s),
  ];
  /** @param {ReturnType<typeof normal>} s */
  function exploreSteps(s) {
    const e = s.evidence, kind = s.target.kind;
    if (!s.target.path || sourceIssue(s)) return [];
    if (kind === 'native') {
      const engine = s.provider === 'ida' ? 'IDA' : 'Ghidra';
      if (!s.opened) return [step('open-target', 'required', 'Open native target', `Starts ${engine} in the background and imports the binary; this can take several minutes. Opening alone is not deep analysis — list functions next.`, 'rea-run', {tool: 'open_binary'})];
      if (!e.functions) return [step('list-functions', 'required', 'List functions', 'Functions → Run analysis retains the provider’s function inventory so you can browse, filter and decompile it.', 'rea-run', {tool: 'list_procedures'})];
      if (!e.decompiled) return [step('decompile-function', 'required', 'Pick a function and Decompile', 'Use Decompile on a row in the Functions table (Browse functions if it is not shown), or type an address in Go to address.', 'evidence-summary'),
        step('search-strings', 'recommended', 'Search strings', 'Strings often reveal features, errors and URLs that lead to the interesting functions.', 'rea-run', {tool: 'search_strings'}),
        ...(e.imports ? [] : [step('list-imports', 'recommended', 'Review imports', 'Imported APIs show what the binary can do (files, network, registry, crypto).', 'rea-run', {tool: 'inspect_pe_imports'})])];
      const idaWrites = s.ida.connected && s.ida.session && s.ida.allowAnnotations;
      return [...(e.annotated ? [] : [step('annotate', 'recommended', 'Rename or comment the function', idaWrites ? 'The IDA bridge is connected with annotations allowed, so names and comments are written to the IDB.' :
          s.ida.connected && s.ida.session ? 'Enable Allow annotations in the IDA Pro panel to write to the IDB; REA session annotations may be refused on Windows.' :
            'REA keeps session annotations, which the provider may refuse on Windows. Connect the IDA Pro bridge for persistent names.', 'code-rename')]),
        step('follow-references', 'recommended', 'Follow callers and xrefs', 'Use Callers, Callees or Xrefs on a function row, or click a highlighted name in the decompiled code.', 'evidence-summary'),
        step('use-in-task', 'recommended', 'Use the evidence in a task', 'Hand the saved record to the coding agent with Use in task.', 'rea-use'),
        ...(s.specialist.enabled && s.specialist.model && s.specialist.connection ? [step('specialist', 'recommended', 'Run the Decompile helper', 'Load the selected function into the Decompile helper (LLM4Decompile) for a C suggestion the agent can review.', 'decompile-input-load')] : [])];
    }
    if (kind === 'dotnet') return e.managed ? [step('managed-members', 'recommended', 'Inspect managed members', 'List types and members from the .NET metadata to find the feature’s entry points.', 'rea-run', {tool: 'inspect_managed_members'})] :
      [step('dotnet-metadata', 'required', 'Inspect .NET metadata', 'This is a managed assembly; its metadata gives types, methods and resources without native decompilation.', 'rea-run', {tool: 'inspect_managed_artifact'})];
    if (kind === 'javascript') return e.javascript ? [step('trace-feature', 'recommended', 'Trace an application feature', 'Follow a feature through the recovered modules and sources.', 'rea-run', {tool: 'trace_application_feature'})] :
      [step('javascript', 'required', 'Analyse the JavaScript / Electron application', 'Recovers the application’s modules, entry points and bundled sources.', 'rea-run', {tool: 'analyze_javascript_application'})];
    if (kind === 'apk') return e.android ? [step('android-classes', 'recommended', 'Search Android classes', 'Find the classes behind the feature you are investigating.', 'rea-run', {tool: 'search_android_classes'})] :
      [step('android', 'required', 'Inspect the Android package', 'Reads the manifest, components and package structure through JADX.', 'rea-run', {tool: 'inspect_android_package'})];
    return Object.values(e).some(Boolean) ? [] : [step('inspect-artifact', 'recommended', 'Inspect the artifact', 'Identify the artifact’s format and contents before choosing a deeper analysis.', 'rea-run', {tool: 'inspect_artifact'})];
  }
  /** @param {ReturnType<typeof normal>} s */
  function rebuildSteps(s) {
    if (!enoughEvidence(s)) return [];
    if (!s.project) return [step('open-project', 'recommended', 'Open a separate destination project', 'Rebuilds are written to their own project outside the original application.', 'open-project')];
    const r = s.reconstruction, providers = s.model ? [] : s.connections ?
      [step('agent-model', 'config', 'Choose the Agent model', 'The next stage prepares a task for the Agent model, which runs every task and calls the analysis tools. Choose it in the Models card.', 'model')] :
      [step('providers', 'config', 'Add a connection', 'The next stage prepares a task for the Agent model. Add a connection (cloud API or local endpoint), then choose the Agent model in the Models card.', 'model', {action: 'providers'})];
    if (r.oracleStatus === 'failed') return [...providers, step('oracle-retry', 'required', '4 · Prepare retry', 'The last oracle run failed. Prepare a retry task from its recorded mismatches.', 'oracle-retry')];
    if (r.oracleStatus === 'passed') return [step('next-milestone', 'recommended', 'Plan the next milestone', 'The declared oracle cases passed. Describe the next feature or milestone and prepare its analysis.', 'reconstruction-goal')];
    if (r.dossier && r.oracleCases === 0) return [step('oracle-cases', 'required', 'Add oracle cases', `Declare commands and expected outputs in ${r.dossier}/oracle-cases.json. An empty suite stays UNVERIFIED.`, 'oracle-run', {action: 'openOracleCases'})];
    if (r.dossier) return [step('oracle-run', 'required', '3 · Run oracle checks', 'Review and approve the exact commands, then run them in Code mode.', 'oracle-run')];
    if (r.brief) return [...providers, step('save-spec', 'required', '2 · Save SPEC & prepare build', 'Your analysis brief is complete. Save it as SPEC.md with the evidence and prepare the build task.', 'reconstruction-build')];
    return [...providers, step('prepare-analysis', 'recommended', '1 · Prepare analysis', 'There is enough evidence to prepare a reconstruction brief. Describe the feature, then prepare the analysis task.', 'reconstruction-analyse')];
  }
  /** Up to `limit` prioritised next steps; dismissed ids and tools the live catalog lacks are skipped.
   * @param {JsonObject} snapshot @param {number} [limit] */
  function nextSteps(snapshot, limit = 3) {
    const s = normal(snapshot), seen = new Set(), out = [];
    for (const rule of guideRules) for (const item of rule(s)) {
      if (seen.has(item.id) || s.dismissed.includes(item.id)) continue;
      if (item.tool && s.rea.tools.length && !s.rea.tools.includes(item.tool)) continue;
      seen.add(item.id); out.push(item);
    }
    return out.slice(0, limit);
  }
  /** Ordered stages with done/current/todo/blocked status. @param {JsonObject} snapshot */
  function reStages(snapshot) {
    const s = normal(snapshot), e = s.evidence, r = s.reconstruction, native = s.target.kind === 'native', issue = sourceIssue(s);
    const labels = /** @type {Record<string,string>} */ ({native: 'Native binary', dotnet: '.NET assembly', javascript: 'JavaScript / Electron', apk: 'Android package', other: 'Other artifact'});
    // Native exploration completes with recovered code; inventories alone keep it current.
    const explored = native ? e.decompiled : e.functions || e.strings || e.imports || e.managed || e.javascript || e.android || e.decompiled;
    /** @type {[string,string,boolean,string,string][]} */
    const rows = [
      ['connect', 'Connect', s.rea.connected && s.rea.catalog, s.rea.connected ? `${s.rea.tools.length} live tools` : 'REA is not connected', ''],
      ['target', 'Target', !!s.target.path, s.target.path ? labels[s.target.kind] || 'Artifact selected' : 'No artifact selected', ''],
      ['source', 'Source', !!s.target.path && !issue, issue || (s.source?.id ? `Using ${s.source.id}` : 'REA live catalog'), issue],
      ['open', 'Open', native ? s.opened : !!s.target.path, native ? s.opened ? 'Opened in this REA session' : 'Not opened in this REA session' : 'Not needed for this artifact type', ''],
      ['explore', 'Explore', !!explored, explored || e.functions || e.strings || e.imports ? [e.functions && 'functions', e.decompiled && 'decompiled', e.strings && 'strings', e.imports && 'imports', e.managed && '.NET metadata', e.javascript && 'JavaScript', e.android && 'Android'].filter(Boolean).join(' · ') : 'No saved exploration results for this target', ''],
      ['annotate', 'Annotate', e.annotated, e.annotated ? 'Names or comments saved' : 'No names or comments yet', ''],
      ['rebuild', 'Rebuild', !!r.dossier, r.dossier ? 'SPEC and evidence saved' : r.brief ? 'Brief completed · save SPEC' : 'No brief yet', ''],
      ['verify', 'Verify', r.oracleStatus === 'passed', r.oracleStatus ? `Last oracle run ${r.oracleStatus}` : r.dossier ? r.oracleCases === 0 ? 'Oracle suite is empty' : 'Oracle checks not run' : 'Nothing to verify yet', ''],
    ];
    let reached = false;
    return rows.map(([id, label, done, detail, blocked]) => {
      const status = done ? 'done' : blocked ? 'blocked' : reached ? 'todo' : 'current';
      if (!done) reached = true;
      return {id, label, status, detail};
    });
  }
  const openFirst = /^(list_procedures|search_procedures|procedure_|xrefs$|list_strings|search_strings|list_names|set_address_name|set_addresses_names|set_comment|set_inline_comment|analyze_function|get_call_graph|read_function_instructions|batch_decompile|find_xrefs_to_name)/;
  /** Missing prerequisite for a chosen REA tool, or null. @param {string} tool @param {JsonObject} snapshot @param {JsonObject} [args] */
  function preflight(tool, snapshot, args = {}) {
    const s = normal(snapshot);
    if (!tool) return null;
    if (!s.rea.connected) return {message: 'Connect REA to load its live tools first.', step: connectStep};
    if (!s.target.path && (tool === 'open_binary' || openFirst.test(tool) || /^(inspect_|analyze_)/.test(tool))) return {message: 'Select an artifact first.', step: targetStep};
    if (/android/.test(tool) && !s.sources.includes('jadx-mcp')) return {message: 'Android tools need the JADX MCP provider.', step: step('configure-jadx', 'config', 'Configure JADX MCP', 'Set up JADX MCP in Toolchain, then reconnect REA.', 'toolchain-open', {action: 'toolchain'})};
    if (openFirst.test(tool) && s.target.kind === 'native' && !s.opened) return {message: `${tool} needs the native target opened in this REA session.`, step: step('open-target', 'required', 'Open native target', 'Starts the native provider in the background.', 'rea-run', {tool: 'open_binary'})};
    if (/^procedure_/.test(tool) && typeof args?.procedure === 'string' && !args.procedure.trim()) return s.evidence.functions ?
      {message: 'Choose a function first.', step: step('decompile-function', 'required', 'Choose a function from Functions', 'Use a row action in the Functions table or Go to address.', 'evidence-summary')} :
      {message: 'List functions first, then choose one.', step: step('list-functions', 'required', 'List functions', 'Retain the function inventory to choose from.', 'rea-run', {tool: 'list_procedures'})};
    return null;
  }
  /** Missing prerequisite for an IDA bridge tool of the given kind, or null. @param {string} kind @param {JsonObject} snapshot */
  function idaPreflight(kind, snapshot) {
    const s = normal(snapshot);
    if (s.ida.unsupported) return {message: 'This build does not include the IDA Pro bridge.', step: null};
    if (!s.ida.installed && !s.ida.connected) return {message: 'The IDA bridge is not installed.', step: step('install-ida', 'config', 'Prepare IDA bridge setup', 'Prepare the bridge setup command, run it in Terminal, then enable the bridge.', 'ida-setup')};
    if (!s.ida.enabled || !s.ida.connected) return {message: 'Enable the IDA bridge first.', step: step('enable-ida', 'config', 'Enable the IDA bridge', 'Headless opens the selected target with idalib; attached uses an open IDA window.', 'ida-enable-headless')};
    if (!s.ida.session) return {message: 'Open the selected target in IDA first.', step: step('open-ida', 'required', 'Open the target in IDA', 'No IDA database is open.', 'ida-open')};
    if (kind === 'annotate' && !s.ida.allowAnnotations) return {message: 'This tool writes to the IDB.', step: step('ida-annotations', 'config', 'Allow annotations', 'Allow rename and comment tools to write to the IDB.', 'ida-annotations')};
    return null;
  }
  return {defaults, issues, nativeView, pageArguments, procedure, sameTarget, visible, cTokens, address, fillArgs, functionRecord,
    filterHistory, historyFacets, sequencer, oraclePlan, formatSize, rawText, rowMatches,
    helperProfile, helperStatus, connectionStatus, helperInputKind, helperInputIssue,
    normalizeEol, fileFormat, indentUnit, lineDiff, diffLines, appendChunks, rememberCommand, recallCommand, activeRunStatuses, runMeta, runMatches, pendingCommand, forceableSkips, gitFileLabel,
    targetKind, kindHint, evidenceSummary, failureInfo, reStages, nextSteps, preflight, idaPreflight};
})();
// @ts-ignore CommonJS export for the Node contract tests; browser use needs no loader.
if (typeof module !== 'undefined' && module.exports) module.exports = QuixiAnalysis;
