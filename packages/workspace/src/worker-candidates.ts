import { sha256 } from './journal.js';
import { validCandidatePath } from './transactions.js';
import type { Candidate, ReadPrecondition, TransactionBroker, TransactionOutcome } from './transactions.js';

type WorkerChange = { file_path?: unknown; before_sha256?: unknown; after_sha256?: unknown; content?: unknown; content_base64?: unknown };
type WorkerResult = { status?: unknown; requested_mode?: unknown; requires_host_commit?: unknown; changes?: unknown; validation?: unknown; context_changes?: unknown; file_operations?: unknown };
export type IndependentValidation = (candidates: readonly Candidate[]) => Promise<{ completed: boolean; passed: boolean; details?: unknown }>;

/** Treat worker output as untrusted data, never as filesystem authority. */
export function normalizeWorkerCandidates(result: unknown, allowedPaths: ReadonlySet<string>, requestedMode: 'preview' | 'apply'): Candidate[] {
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Worker returned an invalid edit candidate.');
  const value = result as WorkerResult;
  const fileOperations = value.file_operations === undefined ? [] : value.file_operations;
  if (!Array.isArray(fileOperations) || fileOperations.length > 1000) throw new Error('Worker returned invalid file operations.');
  if (value.status !== 'candidate' || value.requested_mode !== requestedMode || !Array.isArray(value.changes) || value.changes.length > 1000 || value.requires_host_commit !== (value.changes.length + fileOperations.length > 0)) {
    throw new Error('Worker candidate metadata does not match the authorized request.');
  }
  if (value.context_changes !== undefined && (!Array.isArray(value.context_changes) || value.context_changes.length !== 0)) throw new Error('Context changes require a separately verified transaction.');
  const changes: Candidate[] = value.changes.map((item: unknown) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Worker returned an invalid file candidate.');
    const change = item as WorkerChange;
    if (typeof change.file_path !== 'string' || !validCandidatePath(change.file_path) || !allowedPaths.has(change.file_path)) throw new Error('Worker requested a file outside the authorized operation scope.');
    if ((change.before_sha256 !== null && (typeof change.before_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(change.before_sha256))) || typeof change.after_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(change.after_sha256)) throw new Error('Worker returned an invalid candidate fingerprint.');
    if ((typeof change.content === 'string') === (typeof change.content_base64 === 'string')) throw new Error('Worker candidate needs exactly one byte representation.');
    let bytes: Buffer;
    if (typeof change.content === 'string') {
      if (Buffer.byteLength(change.content, 'utf8') > 64 * 1024 * 1024) throw new Error('Worker candidate exceeds the per-file size limit.');
      bytes = Buffer.from(change.content, 'utf8');
      if (bytes.toString('utf8') !== change.content) throw new Error('Worker candidate contains invalid Unicode.');
    } else {
      const encoded = change.content_base64 as string;
      if (encoded.length > Math.ceil((64 * 1024 * 1024) / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error('Worker candidate has invalid or oversized base64.');
      bytes = Buffer.from(encoded, 'base64');
      if (bytes.toString('base64') !== encoded) throw new Error('Worker candidate has noncanonical base64.');
    }
    if (bytes.length > 64 * 1024 * 1024 || sha256(bytes) !== change.after_sha256) throw new Error('Worker candidate bytes do not match their declared size limit or hash.');
    return { path: change.file_path, before_sha256: change.before_sha256, after_base64: bytes.toString('base64') };
  });
  const scoped = (name: unknown): string => {
    if (typeof name !== 'string' || !validCandidatePath(name) || !allowedPaths.has(name)) throw new Error('Worker requested a file outside the authorized operation scope.');
    return name;
  };
  const fingerprint = (value: unknown): string => {
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new Error('Worker returned an invalid candidate fingerprint.');
    return value;
  };
  for (const operation of fileOperations) {
    if (!operation || typeof operation !== 'object' || Array.isArray(operation)) throw new Error('Worker returned an invalid file operation.');
    const item = operation as Record<string, unknown>;
    const name = scoped(item.file_path);
    if (item.operation === 'delete') {
      if (item.after_sha256 !== null || item.content !== undefined || item.content_base64 !== undefined) throw new Error('Deletion must not supply replacement bytes.');
      changes.push({ path: name, before_sha256: fingerprint(item.before_sha256), after_base64: null });
    } else if (item.operation === 'create' || item.operation === 'rename') {
      const target = item.operation === 'create' ? name : scoped(item.target_file_path);
      const before = item.operation === 'rename' ? fingerprint(item.before_sha256) : null;
      if ((item.operation === 'create' && item.before_sha256 !== null) || (item.operation === 'rename' && (item.target_before_sha256 !== null || target === name || item.after_sha256 !== before))) throw new Error('Creation or rename preconditions are invalid.');
      // Reuse the same exact-byte validator as replacements. The synthetic
      // before digest is only for decoding; creation remains expected absent.
      const decoded = normalizeWorkerCandidates({ status: 'candidate', requested_mode: requestedMode, requires_host_commit: true,
        changes: [{ file_path: target, before_sha256: fingerprint(item.after_sha256), after_sha256: item.after_sha256, content: item.content, content_base64: item.content_base64 }] }, allowedPaths, requestedMode)[0];
      if (!decoded) throw new Error('File operation has no candidate bytes.');
      changes.push({ ...decoded, before_sha256: null });
      if (before !== null) changes.push({ path: name, before_sha256: before, after_base64: null });
    } else throw new Error('Worker requested an unknown file operation.');
  }
  if (changes.length > 1000) throw new Error('Worker returned too many file candidates.');
  return changes;
}

/** The caller, not the worker, selects apply; a separate validator must approve it. */
export async function handleWorkerCandidates(options: {
  result: unknown; allowedPaths: ReadonlySet<string>; mode: 'preview' | 'apply'; broker: TransactionBroker;
  idempotencyKey?: string; validate?: IndependentValidation; signal?: AbortSignal;
  validationRecorder?: (validation: Awaited<ReturnType<IndependentValidation>>) => Promise<void>;
  readPreconditions?: readonly ReadPrecondition[];
}): Promise<TransactionOutcome & { candidate_validation?: unknown }> {
  const candidates = normalizeWorkerCandidates(options.result, options.allowedPaths, options.mode);
  if (candidates.length === 0) return { status: options.mode === 'preview' ? 'preview' : 'completed', files: [], limitations: ['No file changes were proposed.'] };
  if (options.mode === 'preview') {
    const outcome = await options.broker.preview(candidates);
    if (!options.validate) return outcome;
    const validation = await options.validate(candidates);
    return { ...outcome, candidate_validation: validation };
  }
  if (!options.idempotencyKey) throw new Error('Apply requires an idempotency key.');
  if (!options.validate) throw new Error('CANDIDATE_VALIDATION_UNAVAILABLE: apply requires independent validation.');
  const validation = await options.validate(candidates);
  if (validation.completed !== true || validation.passed !== true) throw new Error('CANDIDATE_VALIDATION_INCOMPLETE_OR_FAILED');
  await options.validationRecorder?.(validation);
  const outcome = await options.broker.apply(candidates, options.idempotencyKey, options.signal, options.readPreconditions);
  return { ...outcome, candidate_validation: validation };
}
