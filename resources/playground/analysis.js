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
  return {defaults, issues, nativeView, pageArguments, procedure, sameTarget};
})();
// @ts-ignore CommonJS export for the Node contract tests; browser use needs no loader.
if (typeof module !== 'undefined' && module.exports) module.exports = QuixiAnalysis;
