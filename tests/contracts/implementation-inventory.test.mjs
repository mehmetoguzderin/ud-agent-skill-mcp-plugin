import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const root = path.resolve(import.meta.dirname, '../..');
const python = process.env.UD_AGENT_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');

test('requirements linkage rejects omitted suites, absent/escaped evidence and changed source bytes', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-implementation-linkage-'));
  try {
    for (const name of ['scripts/generate', 'contracts', 'quality', 'src', 'tests']) await mkdir(path.join(directory, name), { recursive: true });
    await cp(path.join(root, 'scripts/generate/implementation-inventory.py'), path.join(directory, 'scripts/generate/implementation-inventory.py'));
    await writeFile(path.join(directory, 'quality/requirements.json'), JSON.stringify({ schema_version: 1, required_suites: ['one', 'two'], required_artifacts: ['package'] }));
    await writeFile(path.join(directory, 'src/impl.py'), 'value = 1\n'); await writeFile(path.join(directory, 'tests/test_impl.py'), 'assert value == 1\n');
    const requirement = { id: 'one', requirement: 'Keep an exact source and test linkage.', authorities: ['quality/requirements.json'], implementation: ['src'], tests: ['tests'], required_suites: ['one', 'two'] };
    const write = row => writeFile(path.join(directory, 'contracts/implementation-requirements.json'), JSON.stringify({ schema_version: 1, requirements: [row] }));
    const run = (...args) => spawnSync(python, ['scripts/generate/implementation-inventory.py', ...args], { cwd: directory, encoding: 'utf8', timeout: 10000 });
    await write(requirement); assert.equal(run().status, 0); assert.equal(run('--check').status, 0);
    const actual = JSON.parse(await readFile(path.join(directory, 'contracts/implementation-inventory.json'), 'utf8'));
    assert.deepEqual(actual.requirements[0].implementation.map(row => row.path), ['src/impl.py']); assert.equal(Object.hasOwn(actual.requirements[0], 'status'), false);
    await writeFile(path.join(directory, 'src/impl.py'), 'value = 2\n'); assert.notEqual(run('--check').status, 0);
    for (const patch of [{ required_suites: ['one'] }, { implementation: ['missing.py'] }, { tests: ['../outside.py'] }, { implementation: [] }]) {
      await write({ ...requirement, ...patch }); const result = run(); assert.equal(result.error, undefined); assert.notEqual(result.status, 0);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('bounded default linkage is additive to legacy exhaustive requirements and covers every declared profile', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-implementation-profiles-'));
  try {
    for (const name of ['scripts/generate', 'contracts', 'quality', 'src', 'tests']) await mkdir(path.join(directory, name), { recursive: true });
    await cp(path.join(root, 'scripts/generate/implementation-inventory.py'), path.join(directory, 'scripts/generate/implementation-inventory.py'));
    const acceptance = { required_suites: ['unit', 'mutation-rust'], required_artifacts: ['package'], default_test_mutation_profile: 'bounded', mutation_profiles: { bounded: { policy: 'bounded-reviewed-v1', suite: 'mutation-bounded', scheduled: 18, exhaustive: false } } };
    const writeAcceptance = value => writeFile(path.join(directory, 'quality/requirements.json'), JSON.stringify(value));
    await writeAcceptance(acceptance);
    await writeFile(path.join(directory, 'src/impl.py'), 'value = 1\n'); await writeFile(path.join(directory, 'tests/test_impl.py'), '# Original test bytes.\n');
    const legacy = { id: 'legacy', requirement: 'Retain the original full-profile linkage.', authorities: ['quality/requirements.json'], implementation: ['src/impl.py'], tests: ['tests/test_impl.py'], required_suites: ['unit', 'mutation-rust'] };
    const bounded = { ...legacy, id: 'bounded', requirement: 'Link the explicit bounded corpus separately.', required_suites: ['mutation-bounded'] };
    const writeRequirements = rows => writeFile(path.join(directory, 'contracts/implementation-requirements.json'), JSON.stringify({ schema_version: 1, requirements: rows }));
    const run = (...args) => spawnSync(python, ['scripts/generate/implementation-inventory.py', ...args], { cwd: directory, encoding: 'utf8', timeout: 10000 });
    await writeRequirements([legacy]); assert.notEqual(run().status, 0);
    await writeRequirements([legacy, bounded]); assert.equal(run().status, 0); assert.equal(run('--check').status, 0);
    const actual = JSON.parse(await readFile(path.join(directory, 'contracts/implementation-inventory.json'), 'utf8'));
    assert.deepEqual(actual.required_suites, acceptance.required_suites);
    assert.equal(actual.default_test_mutation_profile, 'bounded');
    assert.deepEqual(actual.default_required_suites, ['unit', 'mutation-bounded']);
    assert.deepEqual(actual.required_suites_by_profile, { exhaustive: ['unit', 'mutation-rust'], bounded: ['unit', 'mutation-bounded'] });
    assert.deepEqual(new Set(actual.requirements.flatMap(row => row.required_suites)), new Set(actual.required_suite_union));
    assert.deepEqual(actual.requirements[0].required_suites_by_profile.bounded, ['unit']);
    assert.deepEqual(actual.requirements[1].required_suites_by_profile.exhaustive, []);
    await writeAcceptance({ ...acceptance, default_test_mutation_profile: 'unknown' }); assert.notEqual(run().status, 0);
    await writeAcceptance({ ...acceptance, mutation_profiles: { bounded: { ...acceptance.mutation_profiles.bounded, scheduled: 17 } } }); assert.notEqual(run().status, 0);
    const retained = JSON.parse(await readFile(path.join(root, 'contracts/implementation-requirements.json'), 'utf8'));
    assert.deepEqual(retained.requirements.slice(0, 14).map(row => row.id), ['public-catalog', 'workspace-authority', 'mcp-compatibility', 'domain-behavior', 'runtime-selection', 'worker-isolation', 'installed-payloads', 'skills-and-hosts', 'mutation-typescript', 'mutation-python', 'mutation-rust', 'mutation-perl', 'acceptance-reconciliation', 'release-authority']);
    assert.equal(retained.requirements[14].id, 'mutation-bounded');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
