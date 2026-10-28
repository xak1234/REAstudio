const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const cargo = fs.readFileSync(path.join(root, 'Cargo.toml'), 'utf8');
const version = cargo.match(/\[workspace\.package\][\s\S]*?^version\s*=\s*"(\d+\.\d+\.\d+)"/m)?.[1];
if (!version) throw Error('Cargo.toml must declare a numeric workspace release version');
const members = cargo.match(/^members\s*=\s*\[([\s\S]*?)\]/m)?.[1];
if (!members) throw Error('Workspace members were not found');
const packages = [...members.matchAll(/"([^"]+)"/g)].map(([, member]) => {
  const text = fs.readFileSync(path.join(root, member, 'Cargo.toml'), 'utf8');
  const name = text.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
  if (!name) throw Error('Missing package name: ' + member);
  return name;
});
module.exports = { root, version, packages };
