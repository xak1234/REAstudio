import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { root, version, packages } = require('./version.cjs');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const locked = new Map(read('Cargo.lock').split('[[package]]').map(block => [
  block.match(/^name\s*=\s*"([^"]+)"/m)?.[1], block.match(/^version\s*=\s*"([^"]+)"/m)?.[1],
]));
for (const name of packages) assert.equal(locked.get(name), version, 'Workspace lock version differs: ' + name);
assert(read('README.md').includes('# REA Studio V' + version + '\n'), 'README release heading differs');
assert(read('README.md').includes('REA-Studio-' + version + '-x64.zip'), 'README download version differs');
assert(read('CHANGELOG.md').includes('## ' + version + ' — '), 'Add the current changelog entry');
assert(read('docs/release-notes-' + version + '.md').startsWith('REA Studio V' + version), 'Current release notes differ');
const html = read('resources/playground/index.html');
assert.equal(html.split('__REA_STUDIO_VERSION__').length - 1, 3, 'All UI version labels must use the compiled version token');
assert(!/REA Studio V\d/.test(html), 'Do not hard-code the HTML release version');
assert(read('docs/MCP.md').includes('version `' + version + '`'), 'MCP documentation version differs');
const base = process.argv[2] === '--base' ? process.argv[3] : process.env.REA_VERSION_BASE;
if (base && !/^0+$/.test(base)) {
  assert(/^[0-9a-f]{40}$/i.test(base), 'Version comparison requires a full commit SHA');
  const previous = execFileSync('git', ['show', base + ':Cargo.toml'], { cwd: root, encoding: 'utf8' })
    .match(/\[workspace\.package\][\s\S]*?^version\s*=\s*"(\d+\.\d+\.\d+)"/m)?.[1];
  assert(previous, 'Could not read the previous workspace version');
  const old = previous.split('.').map(Number), current = version.split('.').map(Number);
  const changed = current.findIndex((part, i) => part !== old[i]);
  assert(changed >= 0 && current[changed] > old[changed], `Every delivered update needs a higher version: ${previous} -> ${version}. Run node scripts/bump-version.mjs patch.`);
}
if (process.env.GITHUB_REF_TYPE === 'tag') assert.equal(process.env.GITHUB_REF_NAME, 'v' + version, 'Release tag differs from the package version');
console.log('REA Studio version checks passed: ' + version + (base ? ' (increase verified)' : ''));
