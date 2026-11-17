import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, test } from 'vitest';
import { JournalStore, sha256 } from '../../packages/workspace/src/journal.js';
import { GuardedWorkspace, TransactionBroker } from '../../packages/workspace/src/transactions.js';
import type { SecureWorkspace } from '../../packages/workspace/src/transactions.js';
import { planSelection } from '../../packages/workspace/src/plan-state.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
async function fixture(action: (value: { root: string; store: JournalStore; workspace: GuardedWorkspace }) => Promise<void>) {
  const base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-plan-read-check-'))), root = path.join(base, 'bank'), state = path.join(base, 'state');
  try { await mkdir(root); await mkdir(state, { mode: 0o700 }); await writeFile(path.join(root, 'source.txt'), 'before'); await writeFile(path.join(root, 'dependency.txt'), 'ready'); await action({ root, store: await JournalStore.open(state, guard), workspace: await GuardedWorkspace.open(root, guard, [root]) }); }
  finally { await rm(base, { recursive: true, force: true }); }
}
const edit = [{ path: 'source.txt', before_sha256: sha256('before'), after_base64: Buffer.from('after').toString('base64') }];
const conditions = [{ path: 'dependency.txt', sha256: sha256('ready') }, { path: 'absent.txt', sha256: null }];

test('read preconditions are persisted, identity-bound and rechecked after private asset preparation before mutation', () => fixture(async ({ root, store, workspace }) => {
  const original = store.saveAsset.bind(store); let corrupted = false;
  store.saveAsset = async (...args) => { await original(...args); if (!corrupted) { corrupted = true; await writeFile(path.join(root, 'dependency.txt'), 'external'); } };
  const broker = new TransactionBroker(store, workspace);
  await expect(broker.apply(edit, 'private-assets', undefined, conditions)).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED: STALE_DEPENDENCY_PRECONDITION');
  expect(await readFile(path.join(root, 'source.txt'), 'utf8')).toBe('before');
  const id = sha256(`${root}\0private-assets`), journal = await store.load(id);
  expect(journal).toMatchObject({ phase: 'prepared', read_preconditions: [{ path: 'absent.txt', sha256: null }, { path: 'dependency.txt', sha256: sha256('ready') }] });
  expect((await broker.recover(id)).status).toBe('rolled_back'); expect(await readFile(path.join(root, 'dependency.txt'), 'utf8')).toBe('external');
}), 30000);

test('interrupted all-written recovery cannot finalize against changed dependency state', () => fixture(async ({ root, store, workspace }) => {
  const failing: SecureWorkspace = { root: workspace.root, identity: workspace.identity, metadataPreservationVerified: workspace.metadataPreservationVerified, read: name => workspace.read(name), readOptional: name => workspace.readOptional(name), replace: async (name, before, bytes) => { await workspace.replace(name, before, bytes); throw new Error('after atomic replacement'); } };
  await expect(new TransactionBroker(store, failing).apply(edit, 'after-write', undefined, conditions)).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
  await writeFile(path.join(root, 'absent.txt'), 'external file');
  const recovered = await new TransactionBroker(store, workspace).recover(sha256(`${root}\0after-write`));
  expect(recovered).toMatchObject({ status: 'conflict', message: 'STALE_DEPENDENCY_PRECONDITION: absent.txt' });
  expect(await readFile(path.join(root, 'absent.txt'), 'utf8')).toBe('external file'); expect(await readFile(path.join(root, 'source.txt'), 'utf8')).toBe('after');
}), 30000);

test('condition changes cannot reuse a transaction identity and malformed persisted conditions reject', () => fixture(async ({ root, store, workspace }) => {
  const broker = new TransactionBroker(store, workspace);
  expect((await broker.apply(edit, 'bound-conditions', undefined, conditions)).status).toBe('completed');
  await expect(broker.apply(edit, 'bound-conditions', undefined, [{ path: 'dependency.txt', sha256: sha256('different') }])).rejects.toThrow('IDEMPOTENCY_KEY_REUSED');
  const id = sha256(`${root}\0bound-conditions`), journal = await store.load(id);
  for (const invalid of [[{ path: '../escape', sha256: null }], [{ path: 'a', sha256: null }, { path: 'A', sha256: null }], [{ path: 'a', sha256: 'invalid' }], [{ path: 'a', sha256: null, extra: true }]]) {
    await writeFile(path.join(store.root, 'transactions', id, 'journal.json'), JSON.stringify({ ...journal, read_preconditions: invalid }));
    await expect(store.load(id)).rejects.toThrow('Transaction journal is invalid');
  }
}), 30000);

test('dependency graph discovery handles the full action bound without recursion and rejects unknown/cyclic edges', () => {
  const actions = Array.from({ length: 1000 }, (_, index) => ({ id: String(index), depends_on: index ? [String(index - 1)] : [] }));
  const selection = planSelection({ schema_version: 'ud-plan-v1', actions }, ['999']);
  expect(selection.ordered).toEqual(['999']); expect(selection.satisfied).toEqual(Array.from({ length: 999 }, (_, index) => String(index)));
  expect(() => planSelection({ schema_version: 'ud-plan-v1', actions: [{ id: 'a', depends_on: ['missing'] }] }, ['a'])).toThrow('PLAN_DEPENDENCY_MISSING');
  expect(() => planSelection({ schema_version: 'ud-plan-v1', actions: [{ id: 'a', depends_on: ['b'] }, { id: 'b', depends_on: ['a'] }] }, ['a'])).toThrow('PLAN_DEPENDENCY_CYCLE');
  expect(planSelection({ schema_version: 'ud-plan-v1', actions: [{ id: 'a', depends_on: ['b', 'b'] }, { id: 'b', depends_on: [] }] }, ['a']).satisfied).toEqual(['b']);
});

test('a dependency changed during publication prevents completed status and retains recoverable state', () => fixture(async ({ root, store, workspace }) => {
  const interfering: SecureWorkspace = { root: workspace.root, identity: workspace.identity, metadataPreservationVerified: workspace.metadataPreservationVerified, read: name => workspace.read(name), readOptional: name => workspace.readOptional(name), replace: async (name, before, bytes) => { await workspace.replace(name, before, bytes); await writeFile(path.join(root, 'dependency.txt'), 'changed during publication'); } };
  await expect(new TransactionBroker(store, interfering).apply(edit, 'publication', undefined, conditions)).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED: STALE_DEPENDENCY_PRECONDITION');
  const id = sha256(`${root}\0publication`); expect(await store.load(id)).toMatchObject({ phase: 'committing' });
  expect((await new TransactionBroker(store, workspace).recover(id)).status).toBe('conflict');
  expect(await readFile(path.join(root, 'source.txt'), 'utf8')).toBe('after'); expect(await readFile(path.join(root, 'dependency.txt'), 'utf8')).toBe('changed during publication');
}), 30000);

test('recovery rechecks dependency state after its durability replacement and preserves conflicts', () => fixture(async ({ root, store, workspace }) => {
  const interrupted: SecureWorkspace = { root: workspace.root, identity: workspace.identity, metadataPreservationVerified: workspace.metadataPreservationVerified, read: name => workspace.read(name), readOptional: name => workspace.readOptional(name), replace: async (name, before, bytes) => { await workspace.replace(name, before, bytes); throw new Error('injected interruption'); } };
  await expect(new TransactionBroker(store, interrupted).apply(edit, 'recovery-race', undefined, conditions)).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
  const recovery: SecureWorkspace = { ...interrupted, replace: async (name, before, bytes) => { await workspace.replace(name, before, bytes); await writeFile(path.join(root, 'absent.txt'), 'external arrival'); } };
  expect((await new TransactionBroker(store, recovery).recover(sha256(`${root}\0recovery-race`))).status).toBe('conflict');
  expect(await readFile(path.join(root, 'absent.txt'), 'utf8')).toBe('external arrival'); expect(await readFile(path.join(root, 'source.txt'), 'utf8')).toBe('after');
}), 30000);
