import { describe, expect, it, vi } from 'vitest';
import { sha256 } from '../../packages/workspace/src/journal.js';
import { handleWorkerCandidates, normalizeWorkerCandidates } from '../../packages/workspace/src/worker-candidates.js';
import type { TransactionBroker } from '../../packages/workspace/src/transactions.js';

function result(mode: 'preview' | 'apply') {
  return {
    status: 'candidate', requested_mode: mode, requires_host_commit: true,
    changes: [{ file_path: 'bank.conllu', before_sha256: sha256('old'), after_sha256: sha256('new'), content: 'new' }],
    validation: { status: 'passed' }, // Untrusted worker claims are not acceptance evidence.
  };
}

describe('untrusted worker edit candidates', () => {
  it('normalizes authorized create/delete/rename plans and rejects forged rename bytes', () => {
    const payload = { status: 'candidate', requested_mode: 'preview', requires_host_commit: true, changes: [], file_operations: [
      { operation: 'create', file_path: 'created.txt', before_sha256: null, after_sha256: sha256('created'), content: 'created' },
      { operation: 'delete', file_path: 'deleted.txt', before_sha256: sha256('deleted'), after_sha256: null },
      { operation: 'rename', file_path: 'old.txt', target_file_path: 'new.txt', before_sha256: sha256('rename'), target_before_sha256: null, after_sha256: sha256('rename'), content_base64: Buffer.from('rename').toString('base64') },
    ] };
    const allowed = new Set(['created.txt', 'deleted.txt', 'old.txt', 'new.txt']);
    expect(normalizeWorkerCandidates(payload, allowed, 'preview')).toEqual([
      { path: 'created.txt', before_sha256: null, after_base64: Buffer.from('created').toString('base64') },
      { path: 'deleted.txt', before_sha256: sha256('deleted'), after_base64: null },
      { path: 'new.txt', before_sha256: null, after_base64: Buffer.from('rename').toString('base64') },
      { path: 'old.txt', before_sha256: sha256('rename'), after_base64: null },
    ]);
    expect(() => normalizeWorkerCandidates(payload, new Set(['created.txt', 'deleted.txt', 'old.txt']), 'preview')).toThrow('scope');
    const forged = structuredClone(payload); forged.file_operations[2]!.content_base64 = Buffer.from('forged').toString('base64');
    expect(() => normalizeWorkerCandidates(forged, allowed, 'preview')).toThrow('hash');
    const deletion = structuredClone(payload); deletion.file_operations[1]!.content = 'unrequested';
    expect(() => normalizeWorkerCandidates(deletion, allowed, 'preview')).toThrow('Deletion');
  });

  it('checks scope, requested mode, fingerprints, and exact bytes', () => {
    const allowed = new Set(['bank.conllu']);
    expect(normalizeWorkerCandidates(result('preview'), allowed, 'preview')).toEqual([
      { path: 'bank.conllu', before_sha256: sha256('old'), after_base64: Buffer.from('new').toString('base64') },
    ]);
    expect(() => normalizeWorkerCandidates(result('apply'), allowed, 'preview')).toThrow('authorized request');
    expect(() => normalizeWorkerCandidates(result('preview'), new Set(), 'preview')).toThrow('scope');
    const forged = result('preview'); forged.changes[0]!.content = 'tampered';
    expect(() => normalizeWorkerCandidates(forged, allowed, 'preview')).toThrow('hash');
    const traversal = result('preview'); traversal.changes[0]!.file_path = '../outside';
    expect(() => normalizeWorkerCandidates(traversal, new Set(['../outside']), 'preview')).toThrow('scope');
    expect(() => normalizeWorkerCandidates({ ...result('preview'), context_changes: [{ path: 'context' }] }, allowed, 'preview')).toThrow('separately verified');
  });

  it('does not commit based on a worker validation claim or incomplete host validation', async () => {
    const apply = vi.fn();
    const broker = { apply } as unknown as TransactionBroker;
    const options = { result: result('apply'), allowedPaths: new Set(['bank.conllu']), mode: 'apply' as const, broker, idempotencyKey: 'one' };
    await expect(handleWorkerCandidates(options)).rejects.toThrow('CANDIDATE_VALIDATION_UNAVAILABLE');
    await expect(handleWorkerCandidates({ ...options, validate: async () => ({ completed: false, passed: true }) })).rejects.toThrow('CANDIDATE_VALIDATION_INCOMPLETE_OR_FAILED');
    expect(apply).not.toHaveBeenCalled();
  });

  it('requires an explicit idempotency key and independently completed passing validation', async () => {
    const apply = vi.fn().mockResolvedValue({ status: 'completed', files: [], limitations: [] });
    const broker = { apply } as unknown as TransactionBroker;
    const options = { result: result('apply'), allowedPaths: new Set(['bank.conllu']), mode: 'apply' as const, broker };
    await expect(handleWorkerCandidates({ ...options, validate: async () => ({ completed: true, passed: true }) })).rejects.toThrow('idempotency');
    const validated = await handleWorkerCandidates({ ...options, idempotencyKey: 'one', validate: async () => ({ completed: true, passed: true }) });
    expect(validated.status).toBe('completed');
    expect(apply).toHaveBeenCalledTimes(1);
    expect(apply.mock.calls[0]?.[1]).toBe('one');
  });
});
