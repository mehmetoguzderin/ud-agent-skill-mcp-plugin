import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { editRequestKey, MutationRecovery } from '../../packages/coordinator/src/mutation-recovery.js';
import { brokerWorkerResult } from '../../packages/coordinator/src/result-broker.js';
import { captureValidationSnapshot } from '../../packages/workspace/src/snapshot.js';
import { JournalStore, sha256 } from '../../packages/workspace/src/journal.js';
import { GuardedWorkspace, TransactionBroker } from '../../packages/workspace/src/transactions.js';

const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
const original = '# sent_id = a\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n', changed = original.replace('\thi\t', '\thello\t');
it('replays an installed apply before worker execution and rejects changed inputs or reused keys', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-apply-recovery-')));
  try {
    const workspace = path.join(root, 'workspace'), stateRoot = path.join(root, 'state'); await mkdir(workspace);
    await writeFile(path.join(workspace, 'a.conllu'), original); await writeFile(path.join(workspace, 'b.conllu'), original.replace('sent_id = a', 'sent_id = b'));
    const captured = await captureValidationSnapshot(guard, workspace, [workspace]);
    const snapshot = { sha256: captured.sha256, files: captured.files, root_identity: captured.root_identity }; await captured.cleanup();
    const args = { working_tree_path: workspace, token_ref: { tree_ref: { file_path: 'a.conllu', sent_id: 'a' }, token_id: '1' }, lemma: 'hello', edit_options: { mode: 'apply', idempotency_key: 'same-operation' } };
    const input = { operation: 'token_lemma_set', args, guard, stateRoot, grants: [workspace], provenance: { runtime: 'verified-test-worker', image_digest: 'sha256:' + '1'.repeat(64) } };
    const first = (await MutationRecovery.open(input))!;
    try {
      expect(await first.replay()).toBeUndefined();
      const result = { status: 'candidate', requires_host_commit: true, changes: [{ file_path: 'a.conllu', before_sha256: sha256(original), after_sha256: sha256(changed), content: changed }], validation: { status: 'not_run' } };
      const response = await brokerWorkerResult({ operation: input.operation, args, guard, allowedRoots: [workspace], stateRoot, result, snapshot, remember: (result, snapshot) => first.remember(result, snapshot), recordValidation: validation => first.validated(validation), validate: async (staging, files) => {
        expect(files).toEqual(['a.conllu', 'b.conllu']); expect(await readFile(path.join(staging, 'a.conllu'), 'utf8')).toBe(changed); return { completed: true, passed: true };
      } });
      expect(response.transaction).toMatchObject({ status: 'completed' });
    } finally { await first.release(); }
    const second = (await MutationRecovery.open(input))!;
    try {
      const replayed = await second.replay();
      expect(replayed).toMatchObject({ result: { replayed: true, requires_host_commit: false, transaction: { status: 'completed', replayed: true }, validation: { passed: true } }, snapshot: { sha256: snapshot.sha256 }, provenance: input.provenance });
      expect(await readFile(path.join(workspace, 'a.conllu'), 'utf8')).toBe(changed);
      await writeFile(path.join(workspace, 'b.conllu'), 'changed by another writer');
      await expect(second.replay()).rejects.toThrow('IDEMPOTENT_RESULT_STALE');
    } finally { await second.release(); }
    await expect(MutationRecovery.open({ ...input, args: { ...args, lemma: 'a different request' } })).rejects.toThrow('IDEMPOTENCY_KEY_REUSED_OR_WORKSPACE_CHANGED');
  } finally { await rm(root, { recursive: true, force: true }); }
}, 30000);

it('recovers an interrupted multi-file request before repeating any edit and reports rollback explicitly', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-apply-interruption-')));
  try {
    const workspace = path.join(root, 'workspace'), stateRoot = path.join(root, 'state'); await mkdir(workspace); await mkdir(stateRoot, { mode: 0o700 });
    await writeFile(path.join(workspace, 'a.txt'), 'before a'); await writeFile(path.join(workspace, 'b.txt'), 'before b');
    const args = { working_tree_path: workspace, edit_options: { mode: 'apply', idempotency_key: 'interrupted-operation' } };
    const input = { operation: 'treebank_edit', args, guard, stateRoot, grants: [workspace], provenance: { runtime: 'verified-test-worker' } };
    const first = (await MutationRecovery.open(input))!;
    try {
      const files = [{ path: 'a.txt', sha256: sha256('before a'), size: 8 }, { path: 'b.txt', sha256: sha256('before b'), size: 8 }];
      const snapshot = { sha256: sha256(JSON.stringify(files)), files };
      await first.remember({ status: 'candidate', requires_host_commit: true, changes: [], validation: { status: 'not_run' } }, snapshot);
      await first.validated({ completed: true, passed: true });
      const secured = await GuardedWorkspace.open(workspace, guard, [workspace]), replace = secured.replace.bind(secured);
      secured.replace = async (...values) => { await replace(...values); throw new Error('Simulated lost response after first durable replacement.'); };
      const broker = new TransactionBroker(await JournalStore.open(stateRoot, guard), secured);
      await expect(broker.apply([{ path: 'a.txt', before_sha256: sha256('before a'), after_base64: Buffer.from('after a').toString('base64') }, { path: 'b.txt', before_sha256: sha256('before b'), after_base64: Buffer.from('after b').toString('base64') }], first.key)).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
      expect(await readFile(path.join(workspace, 'a.txt'), 'utf8')).toBe('after a');
      expect(await readFile(path.join(workspace, 'b.txt'), 'utf8')).toBe('before b');
    } finally { await first.release(); }
    const resumed = (await MutationRecovery.open(input))!;
    try {
      expect(await resumed.replay()).toMatchObject({ result: { status: 'incomplete', code: 'TRANSACTION_ROLLED_BACK', transaction: { status: 'rolled_back' } } });
      expect(await readFile(path.join(workspace, 'a.txt'), 'utf8')).toBe('before a'); expect(await readFile(path.join(workspace, 'b.txt'), 'utf8')).toBe('before b');
    } finally { await resumed.release(); }
  } finally { await rm(root, { recursive: true, force: true }); }
}, 30000);

it('retains legacy implicit transaction keys and refuses malformed durable intent without holding its lock', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-apply-state-')));
  try {
    const workspace = path.join(root, 'workspace'), stateRoot = path.join(root, 'state'); await mkdir(workspace);
    const args = { working_tree_path: workspace, edit_options: { mode: 'apply' } };
    const input = { operation: 'treebank_edit', args, guard, stateRoot, grants: [workspace], provenance: { runtime: 'fixture' } };
    const key = sha256(JSON.stringify({ operation: input.operation, arguments: args }));
    expect(editRequestKey(input.operation, args)).toBe(key);
    const first = (await MutationRecovery.open(input))!; await first.release();
    const recordPath = path.join(stateRoot, `.request-${sha256(`${workspace}\0${key}`)}.json`);
    const record = JSON.parse(await readFile(recordPath, 'utf8'));
    for (const snapshot of [
      { sha256: 'a'.repeat(64), files: {} },
      { sha256: 'a'.repeat(64), files: [{ path: '../escape', size: 0, sha256: sha256('') }] },
      { sha256: 'a'.repeat(64), files: [{ path: 'a', size: -1, sha256: sha256('') }] },
    ]) {
      await writeFile(recordPath, JSON.stringify({ ...record, snapshot }), { mode: 0o600 });
      await expect(MutationRecovery.open(input)).rejects.toThrow('EDIT_RECOVERY_RECORD_INVALID');
    }
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    const repaired = (await MutationRecovery.open(input))!; await repaired.release();
  } finally { await rm(root, { recursive: true, force: true }); }
}, 30000);
