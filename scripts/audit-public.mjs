import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const excluded = new Set(['.git', 'target', 'dist', 'node_modules', 'node', 'ghidra', 'jdk', 'sources', 'toolchain']);
function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (excluded.has(entry.name)) return [];
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(file) : [path.relative(root, file).replaceAll('\\', '/')];
  });
}
let files;
try { files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\0').filter(Boolean); }
catch { files = walk(root); }
if (!files.length) files = walk(root);
const problems = [];
const forbiddenPath = /(^|\/)(\.env(?:\..*)?|providers\.json|projects\.json|rea-plugin\.json|\.quixi|\.agents|\.mcp\.json)(\/|$)|\.(exe|dll|node|zip|gguf|log|dmp)$/i;
const privateAddress = /\b192\.168\.\d{1,3}\.\d{1,3}\b/;
const secret = /(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-(?:ant-)?[A-Za-z0-9_-]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/;
for (const file of files) {
  if (forbiddenPath.test(file)) problems.push(`${file}: runtime, credential or generated file is tracked`);
  if (/^resources\/(renderer|ion-dist|fonts|bootstrap|preload|bundled-skills)/.test(file)) problems.push(`${file}: excluded legacy resource tree`);
  const bytes = fs.readFileSync(path.join(root, file));
  if (bytes.length > 10 * 1024 * 1024) problems.push(`${file}: unexpected large source file`);
  if (bytes.includes(0)) continue;
  const text = bytes.toString('utf8');
  if (privateAddress.test(text)) problems.push(`${file}: private LAN address`);
  if (/https?:\/\/[^\s"'<>]+[?&](?:key|token|access_token)=[A-Za-z0-9_-]{12,}/i.test(text)) problems.push(`${file}: possible credential-bearing URL`);
  if (secret.test(text)) problems.push(`${file}: possible embedded credential`);
}
if (problems.length) {
  console.error(problems.join('\n'));
  process.exitCode = 1;
} else console.log(`Public source audit passed (${files.length} files). This bounded check is not a substitute for reviewing new secrets or licenses.`);
