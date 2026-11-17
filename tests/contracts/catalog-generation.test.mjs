import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const root = path.resolve(import.meta.dirname, '../..');
const python = process.env.UD_AGENT_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
const inputs = ['ud-interfaces.json', 'environment.json', 'input-shapes.json', 'result-shapes.json'];
const run = directory => spawnSync(python, ['scripts/generate/contracts.py'], { cwd: directory, encoding: 'utf8', timeout: 45000, maxBuffer: 1024 * 1024 });

test('canonical catalogs generate all shared bindings with no prose input and preserve the frozen 104 public entries', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-catalog-generation-'));
  try {
    await mkdir(path.join(directory, 'scripts/generate'), { recursive: true });
    await mkdir(path.join(directory, 'contracts'));
    await cp(path.join(root, 'scripts/generate/contracts.py'), path.join(directory, 'scripts/generate/contracts.py'));
    const original = new Map();
    for (const name of inputs) { const bytes = await readFile(path.join(root, 'contracts', name)); original.set(name, bytes); await writeFile(path.join(directory, 'contracts', name), bytes); }
    const result = run(directory);
    assert.equal(result.error, undefined, result.stderr); assert.equal(result.status, 0, result.stderr);
    for (const name of inputs) assert.deepEqual(await readFile(path.join(directory, 'contracts', name)), original.get(name), name);
    const domain = JSON.parse(original.get('ud-interfaces.json')), environment = JSON.parse(original.get('environment.json'));
    const frozen = JSON.parse(await readFile(path.join(root, 'tests/fixtures/compatibility/104-tools-v1.json'), 'utf8'));
    assert.deepEqual([...domain, ...environment], frozen.tools);
    assert.deepEqual(JSON.parse(await readFile(path.join(directory, 'contracts/ud-interfaces.yaml'), 'utf8')), domain);
    for (const row of frozen.tools) {
      const input = JSON.parse(await readFile(path.join(directory, 'contracts/schema/operations', row.name + '.input.schema.json'), 'utf8'));
      const output = JSON.parse(await readFile(path.join(directory, 'contracts/schema/results', row.name + '.schema.json'), 'utf8'));
      assert.equal(input.title, row.name); assert.deepEqual(Object.keys(input.properties), row.parameters.map(item => item.name));
      assert.equal(output.properties.operation.const, row.name); assert.equal(output.properties.operation_id.const, row.id);
    }
    for (const patch of [{ id: '002' }, { original_signature: 'treebank_create(unrelated)' }, { handler: 'ud_agent.domain.workspace:unrelated' }, { access: { writes_workspace: 'true' } }]) {
      await writeFile(path.join(directory, 'contracts/ud-interfaces.json'), JSON.stringify([{ ...domain[0], ...patch }, ...domain.slice(1)]));
      const rejected = run(directory); assert.equal(rejected.error, undefined); assert.notEqual(rejected.status, 0); assert.match(rejected.stderr, /canonical/);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
}, 60000);
