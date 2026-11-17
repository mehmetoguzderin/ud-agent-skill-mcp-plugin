import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { captureValidationSnapshot } from '../../packages/workspace/src/snapshot.js';
import { brokerWorkerResult } from '../../packages/coordinator/src/result-broker.js';
import { exportWorkerArtifacts } from '../../packages/coordinator/src/export-broker.js';
import { GuardedWorkspace } from '../../packages/workspace/src/transactions.js';

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
const before = '# sent_id = one\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n';
const after = before.replace('\thi\t', '\thello\t');

describe('public result and export brokers with the actual native helper', () => {
  it('validates exact staged candidate bytes before applying and restricts selected write scope', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-result-broker-')));
    try {
      const workspace = path.join(root, 'workspace'); await mkdir(workspace);
      await writeFile(path.join(workspace, 'a.conllu'), before); await writeFile(path.join(workspace, 'b.conllu'), before.replace('one', 'two'));
      const captured = await captureValidationSnapshot(guard, workspace, [workspace]);
      const snapshot = { sha256: captured.sha256, files: captured.files }; await captured.cleanup();
      const args = { working_tree_path: workspace, token_ref: { tree_ref: { file_path: 'a.conllu', sent_id: 'one' }, token_id: '1' }, edit_options: { mode: 'apply', idempotency_key: 'lemma-request' } };
      const result = { status: 'candidate', requested_mode: 'apply', requires_host_commit: true, changes: [{ file_path: 'a.conllu', before_sha256: hash(before), after_sha256: hash(after), content: after }] };
      let calls = 0;
      const input = { operation: 'token_lemma_set', args, result, snapshot, guard, allowedRoots: [workspace], stateRoot: path.join(root, 'state'), validate: async (staging: string, files: string[]) => { calls++; expect(await readFile(path.join(staging, 'a.conllu'), 'utf8')).toBe(after); expect(files).toEqual(['a.conllu', 'b.conllu']); return { completed: true, passed: false }; } };
      await expect(brokerWorkerResult(input)).rejects.toThrow('CANDIDATE_VALIDATION_INCOMPLETE_OR_FAILED');
      expect(await readFile(path.join(workspace, 'a.conllu'), 'utf8')).toBe(before); expect(calls).toBe(1);
      await expect(brokerWorkerResult({ ...input, result: { ...result, changes: [{ ...result.changes[0], file_path: 'b.conllu' }] } })).rejects.toThrow('outside the authorized operation scope');
      const committed = await brokerWorkerResult({ ...input, validate: async (staging: string) => ({ completed: (await readFile(path.join(staging, 'a.conllu'), 'utf8')) === after, passed: true }) });
      expect(committed.transaction).toMatchObject({ status: 'completed' });
      expect(await readFile(path.join(workspace, 'a.conllu'), 'utf8')).toBe(after);
    } finally { await rm(root, { recursive: true, force: true }); }
  }, 30_000);

  it('exports exact artifacts, reuses identical bytes and rejects unauthorized or conflicting destinations', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-export-broker-')));
    try {
      const destination = path.join(root, 'out'); await mkdir(destination);
      const bytes = Buffer.from('offline result\n');
      const result = { status: 'complete', requires_broker_export: true, artifacts: [{ relative_path: 'report.txt', mime_type: 'text/plain; charset=utf-8', size_bytes: bytes.length, sha256: hash(bytes), content_base64: bytes.toString('base64') }] };
      const input = { args: { working_tree_path: root, output_dir_path: destination }, result, guard, allowedRoots: [root], stateRoot: path.join(root, 'export-state') };
      expect((await exportWorkerArtifacts(input)).export_transaction).toMatchObject({ status: 'completed' });
      expect(await readFile(path.join(destination, 'report.txt'))).toEqual(bytes);
      expect((await exportWorkerArtifacts(input)).export_transaction).toMatchObject({ replayed: true });
      await writeFile(path.join(destination, 'report.txt'), 'changed');
      await expect(exportWorkerArtifacts(input)).rejects.toThrow('EXPORT_DESTINATION_EXISTS');
      await expect(exportWorkerArtifacts({ ...input, allowedRoots: [] })).rejects.toThrow('outside');
      await expect(exportWorkerArtifacts({ ...input, result: { ...result, artifacts: [{ ...result.artifacts[0], sha256: '0'.repeat(64) }] } })).rejects.toThrow('INTEGRITY');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('rolls back an interrupted export before retrying exact bytes and honors cancellation before writes', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-export-recovery-')));
    let replacement: ReturnType<typeof vi.spyOn> | undefined;
    try {
      const destination = path.join(root, 'out'); await mkdir(destination);
      await writeFile(path.join(destination, 'a.txt'), 'before a'); await writeFile(path.join(destination, 'b.txt'), 'before b');
      const result = { status: 'complete', requires_broker_export: true, artifacts: ['a', 'b'].map(name => {
        const bytes = Buffer.from(`after ${name}`); return { relative_path: `${name}.txt`, mime_type: 'text/plain', size_bytes: bytes.length, sha256: hash(bytes), content_base64: bytes.toString('base64') };
      }) };
      const input = { args: { working_tree_path: root, output_dir_path: destination, options: { output_conflict_policy: 'replace' } }, result, guard, allowedRoots: [root], stateRoot: path.join(root, 'state') };
      const controller = new AbortController(); controller.abort();
      await expect(exportWorkerArtifacts({ ...input, signal: controller.signal })).rejects.toThrow('WORKER_CANCELLED');
      expect(await readFile(path.join(destination, 'a.txt'), 'utf8')).toBe('before a');
      const original = GuardedWorkspace.prototype.replace; let interrupted = false;
      replacement = vi.spyOn(GuardedWorkspace.prototype, 'replace').mockImplementation(async function (this: GuardedWorkspace, ...args) {
        await original.apply(this, args);
        if (!interrupted) { interrupted = true; throw new Error('Simulated lost response after durable file publication.'); }
      });
      await expect(exportWorkerArtifacts(input)).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
      expect(await readFile(path.join(destination, 'a.txt'), 'utf8')).toBe('after a'); expect(await readFile(path.join(destination, 'b.txt'), 'utf8')).toBe('before b');
      replacement.mockRestore(); replacement = undefined;
      expect((await exportWorkerArtifacts(input)).export_transaction).toMatchObject({ status: 'completed' });
      for (const name of ['a', 'b']) expect(await readFile(path.join(destination, `${name}.txt`), 'utf8')).toBe(`after ${name}`);
      expect((await exportWorkerArtifacts(input)).export_transaction).toMatchObject({ status: 'completed', replayed: true });
      await writeFile(path.join(destination, 'a.txt'), 'another writer');
      expect((await exportWorkerArtifacts(input)).export_transaction).toMatchObject({ status: 'completed' });
      expect(await readFile(path.join(destination, 'a.txt'), 'utf8')).toBe('after a');
    } finally { replacement?.mockRestore(); await rm(root, { recursive: true, force: true }); }
  }, 30000);
});
