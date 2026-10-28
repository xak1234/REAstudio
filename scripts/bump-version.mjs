import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { root, version, packages } = require('./version.cjs');
const level = process.argv[2] || 'patch';
if (!['patch', 'minor', 'major'].includes(level) || process.argv.slice(3).some(a => a !== '--dry-run')) {
  throw Error('Usage: node scripts/bump-version.mjs [patch|minor|major] [--dry-run]');
}
const parts = version.split('.').map(Number);
const index = { major: 0, minor: 1, patch: 2 }[level];
parts[index]++;
for (let i = index + 1; i < parts.length; i++) parts[i] = 0;
const next = parts.join('.');
const edits = new Map();
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
edits.set('Cargo.toml', read('Cargo.toml').replace(
  /(\[workspace\.package\][\s\S]*?^version\s*=\s*")[^"]+(".*$)/m, (_, before, after) => before + next + after));
const seen = new Set();
edits.set('Cargo.lock', read('Cargo.lock').split('[[package]]').map(block => {
  const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
  if (!packages.includes(name)) return block;
  if (/^source\s*=/m.test(block)) throw Error('Workspace package unexpectedly has an external source: ' + name);
  seen.add(name);
  return block.replace(/^version\s*=\s*"[^"]+"/m, 'version = "' + next + '"');
}).join('[[package]]'));
if (seen.size !== packages.length) throw Error('Cargo.lock is missing workspace packages');
edits.set('README.md', read('README.md')
  .replace(/^# REA Studio V[\d.]+$/m, '# REA Studio V' + next)
  .replace(/^\*\*V[\d.]+ \(package version [\d.]+\)\.\*\*/m, '**V' + next + ' (package version ' + next + ').**')
  .replaceAll('REA-Studio-' + version + '-x64', 'REA-Studio-' + next + '-x64'));
for (const name of ['docs/MCP.md', 'docs/RELEASING.md']) edits.set(name, read(name).replaceAll(version, next));
if (!process.argv.includes('--dry-run')) for (const [name, text] of edits) fs.writeFileSync(path.join(root, name), text);
console.log(`${process.argv.includes('--dry-run') ? 'Would update' : 'Updated'} REA Studio ${version} -> ${next}; ${seen.size} workspace packages. Add the matching changelog entry and release notes before packaging.`);
