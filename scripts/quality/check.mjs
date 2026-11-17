import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import Ajv2020 from 'ajv/dist/2020.js';
import { canonicalSkillFiles } from '../generate/skill-files.mjs';
import { loadWorkflowCorpus } from './workflow-corpus.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (name) => JSON.parse(readFileSync(path.join(root, name), 'utf8'));
const domain = read('contracts/ud-interfaces.json');
const environment = read('contracts/environment.json');
if (domain.length !== 102 || environment.length !== 2) throw new Error('Expected 102 domain tools and two environment tools.');
const names = new Set();
const ajv = new Ajv2020({ strict: true });
for (const [index, item] of [...domain, ...environment].entries()) {
  const expected = index < 102 ? String(index + 1).padStart(3, '0') : `ENV-00${index - 101}`;
  if (item.id !== expected || names.has(item.name)) throw new Error(`Invalid or duplicate operation: ${item.name}`);
  names.add(item.name);
  const schema = read(`contracts/schema/operations/${item.name}.input.schema.json`);
  ajv.compile(schema);
  if (schema.title !== item.name || schema.type !== 'object' || schema.additionalProperties !== false)
    throw new Error(`Invalid operation schema: ${item.name}`);
  const outputPath = item.output_schema ?? `contracts/schema/results/${item.name}.schema.json`;
  const output = read(outputPath);
  ajv.compile(output);
  if (output.title !== `${item.name} result` || output.type !== 'object' || !output.required?.includes('execution') || output.properties?.operation?.const !== item.name || output.properties?.operation_id?.const !== item.id) throw new Error(`Invalid operation result schema: ${item.name}`);
}
const resultNames = readdirSync(path.join(root, 'contracts/schema/results')).filter(name => name.endsWith('.schema.json'));
if (resultNames.length !== 104 || resultNames.some(name => !names.has(name.replace(/\.schema\.json$/, '')))) throw new Error('Generated result schema inventory differs from the 104-tool catalog.');
for (const name of ['contracts/schema/runtime-lock.schema.json', 'runtime/runtime-lock.schema.json']) if (existsSync(path.join(root, name))) {
  const validate = new Ajv2020({ strict: true }).compile(read(name));
  if (!validate(read('runtime/runtime.lock.json'))) throw new Error(`Runtime lock does not match ${name}: ${JSON.stringify(validate.errors)}`);
}
for (const skill of ['ud-validate', 'ud-edit', 'ud-investigate', 'ud-compare', 'ud-rules-docs', 'ud-release']) {
  const file = readFileSync(path.join(root, 'skills', skill, 'SKILL.md'), 'utf8');
  if (!file.startsWith(`---\nname: ${skill}\n`) || !/^description: \S/m.test(file)) throw new Error(`Invalid skill: ${skill}`);
}
canonicalSkillFiles(root);
loadWorkflowCorpus(root);
const python = process.env.UD_AGENT_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
for (const [command, args] of [
  [python, ['scripts/generate/contracts.py', '--check']],
  [process.execPath, ['scripts/generate/public-contracts.mjs', '--check']],
  [process.execPath, ['scripts/generate/maintenance.mjs', '--check']],
  [python, ['scripts/generate/implementation-inventory.py', '--check']],
  [python, ['scripts/generate/unicode-paths.py', '--check']],
  [process.execPath, ['scripts/generate/host-adapters.mjs', '--check']],
  [process.execPath, [path.join(root, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json', '--noEmit']],
  [process.execPath, [path.join(root, 'node_modules/typescript-compat/bin/tsc'), '--allowJs', '--checkJs', '--noEmit', '--target', 'es2024', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--skipLibCheck', '--ignoreConfig', '--strict', 'false', '--types', 'node', 'scripts/release/prepare.mjs', 'scripts/runtime/freeze-runtime.mjs']],
  [python, ['scripts/quality/audit_handlers.py']],
]) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit' });
  if (result.error || result.status !== 0) process.exit(result.status || 1);
}
console.log('Static contract, skill, type, and handler checks passed.');
