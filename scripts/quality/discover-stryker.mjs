#!/usr/bin/env node
/** Independent complete Stryker generation: parses sources, never runs tests. */
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Instrumenter } from '@stryker-mutator/instrumenter';
import { sourceReceipt } from '../release/candidate.mjs';
import { mutationDefinition } from './mutation-inventory.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
import { nodeDependencyInventory } from './node-dependencies.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const demand = (value, message) => { if (!value) throw new Error(`Stryker discovery: ${message}`); };

export async function discoverStryker(root) {
  root = realpathSync(root);
  const source = sourceReceipt(root);
  const require = createRequire(import.meta.url);
  demand(require('@stryker-mutator/instrumenter/package.json').version === '10.1.1', 'locked instrumenter is required');
  const lock = JSON.parse(readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  demand(lock.packages?.['node_modules/@stryker-mutator/instrumenter']?.version === '10.1.1', 'source dependency lock omits the actual instrumenter');
  const dependencies = nodeDependencyInventory(path.resolve(path.dirname(require.resolve('@stryker-mutator/instrumenter')), '../../../..'));
  const files = source.files.filter(item => /^(?:packages|workers|scripts|evals)\//.test(item.path) && !item.path.includes('/tests/') && /\.(?:ts|tsx|mts|cts|js|mjs|cjs)$/.test(item.path));
  demand(files.length > 0, 'applicable source scope is empty');
  const inputs = files.map(item => {
    const bytes = readFileSync(path.join(root, item.path)), content = bytes.toString('utf8');
    demand(sha(bytes) === item.sha256 && Buffer.from(content).equals(bytes), 'source changed or is not UTF-8');
    return { name: path.join(root, item.path), content, mutate: true };
  });
  const logger = Object.fromEntries(['trace', 'debug', 'info', 'warn', 'error', 'fatal'].map(name => [name, () => {}]));
  logger.isDebugEnabled = () => false;
  const options = { excludedMutations: [], ignorers: [] };
  const generated = await new Instrumenter(logger).instrument(inputs, options);
  const sources = new Map(inputs.map(item => [item.name, item.content]));
  const ids = new Set(), definitions = new Set();
  const mutants = generated.mutants.map(mutant => {
    const file = path.relative(root, mutant.fileName).split(path.sep).join('/');
    const value = mutationDefinition(file, sources.get(mutant.fileName), mutant);
    const canonicalId = `${file}#${value.definition_sha256}`;
    demand(!ids.has(value.id) && !definitions.has(canonicalId), 'duplicate generated identity or definition');
    ids.add(value.id); definitions.add(canonicalId);
    return { ...value, id: canonicalId, raw_id: value.id, ...(mutant.status ? { applicability: mutant.status, applicability_reason: mutant.statusReason ?? null } : {}) };
  });
  const materialization = files.map(file => {
    const rows = mutants.filter(mutant => mutant.file === file.path).map(({ id, raw_id, source_sha256, definition_sha256 }) => ({ id, raw_id, source_sha256, definition_sha256 }));
    return { path: file.path, source_sha256: file.sha256, generated: rows.length, inventory_sha256: sha(canonicalJson(rows)) };
  });
  demand(sourceReceipt(root).sha256 === source.sha256, 'source changed during generation');
  return { schema_version: 1, inventory_only: true, qualification: 'complete-operator-discovery-no-outcomes', tool: 'stryker', tool_version: '10.1.1',
    source_tree_sha256: source.sha256, options, source_scope: files.map(({ path, sha256 }) => ({ path, source_sha256: sha256 })), materialization,
    runtime: { executable_sha256: sha(readFileSync(process.execPath)), node_version: process.version, os: process.platform, architecture: process.arch,
      package_lock_sha256: sha(readFileSync(path.join(root, 'package-lock.json'))), instrumenter_entry_sha256: sha(readFileSync(require.resolve('@stryker-mutator/instrumenter'))), dependency_closure_sha256: sha(canonicalJson(dependencies)), dependency_closure: dependencies },
    scheduled: mutants.length, mutants };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [flag, filename] = process.argv.slice(2);
  demand(flag === '--output' && filename && process.argv.length === 4 && !existsSync(filename), 'usage: discover-stryker.mjs --output NEW_JSON');
  const report = await discoverStryker('.');
  mkdirSync(path.dirname(path.resolve(filename)), { recursive: true });
  writeFileSync(filename, JSON.stringify(report) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ qualification: report.qualification, sources: report.source_scope.length, scheduled: report.scheduled, output: path.resolve(filename) }));
}
