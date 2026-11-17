import { lstat, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { GuardedWorkspace, TransactionBroker, validCandidatePath } from '../../workspace/src/transactions.js';
import type { Candidate } from '../../workspace/src/transactions.js';
import { JournalStore, sha256 } from '../../workspace/src/journal.js';
import { decodeWorkerArtifact } from './worker-artifacts.js';
import { guardedIdentity, guardedStateLock } from '../../workspace/src/guard.js';
import { portablePathKey } from '../../workspace/src/portable-path.js';

function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }

/** Export exact verified artifact bytes only to caller-authorized destinations. */
export async function exportWorkerArtifacts(input: { args: Record<string, unknown>; result: Record<string, unknown>; guard: string; allowedRoots: readonly string[]; stateRoot: string; signal?: AbortSignal }): Promise<Record<string, unknown>> {
  if (input.result.requires_broker_export !== true && input.result.requires_host_export !== true) return input.result;
  const cancelled = () => { if (input.signal?.aborted) throw new Error('WORKER_CANCELLED'); };
  cancelled();
  if (!Array.isArray(input.result.artifacts) || input.result.artifacts.length === 0 || input.result.artifacts.length > 1000) throw new Error('WORKER_EXPORT_MANIFEST_INVALID');
  const working = input.args.working_tree_path;
  const single = input.args.output_path;
  const directory = input.args.output_dir_path;
  const destination = single ?? directory;
  if (typeof working !== 'string' || typeof destination !== 'string' || !destination || destination.includes('\0') || (single !== undefined && directory !== undefined)) throw new Error('An explicit authorized export destination is required.');
  if (single !== undefined && input.result.artifacts.length !== 1) throw new Error('Single-file export requires exactly one artifact.');
  const output = path.isAbsolute(destination) ? path.resolve(destination) : path.resolve(working, destination);
  let root = single !== undefined ? path.dirname(output) : output;
  for (let count = 0; ; count++) {
    if (count > 128) throw new Error('EXPORT_DESTINATION_INVALID');
    try { const info = await lstat(root); if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('EXPORT_DESTINATION_INVALID'); break; }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; const parent = path.dirname(root); if (parent === root) throw error; root = parent; }
  }
  const workspace = await GuardedWorkspace.open(root, input.guard, input.allowedRoots);
  const options = object(input.args.options) ?? {};
  const conflict = options.output_conflict_policy ?? 'error';
  if (!['error', 'replace', 'skip-identical'].includes(conflict as string)) throw new Error('Unknown export conflict policy.');
  const seen = new Set<string>(); const exports: { path: string; sha256: string; size_bytes: number }[] = [], decoded: { relative: string; bytes: Buffer; sha256: string }[] = [];
  let total = 0;
  for (const value of input.result.artifacts) {
    cancelled();
    const artifact = decodeWorkerArtifact(value);
    const bytes = artifact.bytes; total += bytes.length;
    if (total > 512 * 1024 * 1024) throw new Error('WORKER_ARTIFACT_INTEGRITY_FAILED');
    const target = single !== undefined ? output : path.join(output, ...artifact.relativePath.split('/'));
    const relative = path.relative(root, target).split(path.sep).join('/');
    if (!validCandidatePath(relative) || seen.has(portablePathKey(relative))) throw new Error('WORKER_EXPORT_DESTINATION_INVALID');
    seen.add(portablePathKey(relative));
    decoded.push({ relative, bytes, sha256: artifact.sha256 });
    exports.push({ path: target, sha256: artifact.sha256, size_bytes: bytes.length });
  }
  cancelled();
  await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
  const store = await JournalStore.open(input.stateRoot, input.guard), broker = new TransactionBroker(store, workspace);
  const requestKey = sha256(JSON.stringify({ destination: output, exports }));
  const release = await guardedStateLock(input.guard, store.root, `.export-${requestKey}.native`, await guardedIdentity(input.guard, store.root));
  try {
  let key = requestKey;
  let recovered: Awaited<ReturnType<TransactionBroker['recover']>> | undefined;
  for (let attempt = 0; ; attempt++) {
    cancelled();
    if (attempt >= 32) throw new Error('EXPORT_RECOVERY_ATTEMPT_LIMIT');
    key = attempt === 0 ? requestKey : sha256(`${requestKey}\0retry-${attempt}`);
    const id = sha256(`${workspace.root}\0${key}`), journal = await store.load(id);
    if (!journal) break;
    // The manifest and grant are checked before any recovery. A damaged or
    // unrelated private journal cannot supply a new export destination.
    const expected = new Map(decoded.map(file => [file.relative, file.sha256]));
    if (journal.entries.some(entry => expected.get(entry.path) !== entry.after)) throw new Error('EXPORT_RECOVERY_MANIFEST_MISMATCH');
    recovered = await broker.recover(id);
    if (recovered.status === 'completed') {
      let identical = true;
      for (const file of decoded) { const current = await workspace.readOptional(file.relative); if (current === null || sha256(current) !== file.sha256) identical = false; }
      if (identical) break;
      if (conflict !== 'replace') throw new Error('EXPORT_DESTINATION_EXISTS');
      recovered = undefined; continue;
    }
    if (recovered.status !== 'rolled_back') return { ...input.result, status: 'incomplete', code: 'EXPORT_RECOVERY_CONFLICT', export_transaction: recovered };
    recovered = undefined;
  }
  const candidates: Candidate[] = [];
  if (!recovered) for (const file of decoded) {
    cancelled();
    const before = await workspace.readOptional(file.relative);
    if (before !== null && sha256(before) === file.sha256) continue;
    if (before !== null && conflict !== 'replace') throw new Error('EXPORT_DESTINATION_EXISTS');
    candidates.push({ path: file.relative, before_sha256: before === null ? null : sha256(before), after_base64: file.bytes.toString('base64') });
  }
  cancelled();
  const transaction = recovered ?? (candidates.length ? await broker.apply(candidates, key, input.signal) : { status: 'completed', replayed: true, files: [] });
  for (const item of exports) {
    const bytes = await workspace.read(path.relative(root, item.path).split(path.sep).join('/'));
    if (sha256(bytes) !== item.sha256 || bytes.length !== item.size_bytes) throw new Error('EXPORTED_BYTES_CHANGED');
  }
  return { ...input.result, requires_broker_export: false, requires_host_export: false, exports, export_transaction: transaction };
  } finally { await release(); }
}
