import { mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import { guardedIdentity, guardedStateLock } from '../../workspace/src/guard.js';
import { GuardedWorkspace, TransactionBroker, transactionRequestHash } from '../../workspace/src/transactions.js';
import { boundedRead, durableWrite, JournalStore, openStateAuthority, sha256 } from '../../workspace/src/journal.js';
import type { NativeState } from '../../workspace/src/journal.js';
import { portablePathKey, validPortablePath } from '../../workspace/src/portable-path.js';
import { actionSetHash, canonical as planCanonical, completedPlanBatch } from '../../workspace/src/plan-completions.js';
import type { CompletedPlanBatch } from '../../workspace/src/plan-completions.js';
import { planSelection } from '../../workspace/src/plan-state.js';
import { verifyPublishedPlanContext } from './context-broker.js';
import type { ResourceStore } from './resources.js';

type Snapshot = { root_identity?: { device: string; inode: string }; sha256: string; files: { path: string; sha256: string; size: number }[]; source_map?: { snapshot_path: string; original_path: string }[] };
type RecordV1 = { version: 1; operation: string; request_hash: string; workspace: string; identity: { device: string; inode: string }; result?: Record<string, unknown>; snapshot?: Snapshot; validation?: { completed: boolean; passed: boolean; details?: unknown }; provenance: Record<string, unknown>; plan_completion?: CompletedPlanBatch; plan_dependencies?: CompletedPlanBatch[] };
function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function canonical(value: unknown): string { return JSON.stringify(value, (_key, selected) => selected && typeof selected === 'object' && !Array.isArray(selected) ? Object.fromEntries(Object.entries(selected).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : selected); }
function recoveryRecord(value: unknown): RecordV1 {
  const record = object(value), identity = object(record?.identity);
  const invalid = () => { throw new Error('EDIT_RECOVERY_RECORD_INVALID'); };
  if (!record || record.version !== 1 || typeof record.operation !== 'string' || !/^[0-9a-f]{64}$/.test(String(record.request_hash)) || typeof record.workspace !== 'string' || !path.isAbsolute(record.workspace) || !identity || typeof identity.device !== 'string' || !identity.device || typeof identity.inode !== 'string' || !identity.inode || !object(record.provenance)) return invalid();
  if (record.result !== undefined && !object(record.result)) return invalid();
  if (record.snapshot !== undefined) {
    const snapshot = object(record.snapshot);
    if (!snapshot || !Array.isArray(snapshot.files) || snapshot.files.length > 10_000 || !/^[0-9a-f]{64}$/.test(String(snapshot.sha256))) return invalid();
    const paths = new Set<string>(); let total = 0;
    for (const entry of snapshot.files) {
      const file = object(entry);
      if (!file || typeof file.path !== 'string' || !validPortablePath(file.path) || !Number.isSafeInteger(file.size) || (file.size as number) < 0 || (file.size as number) > 64 * 1024 * 1024 || !/^[0-9a-f]{64}$/.test(String(file.sha256))) return invalid();
      const key = portablePathKey(file.path); if (paths.has(key)) return invalid(); paths.add(key); total += file.size as number;
    }
    if (total > 512 * 1024 * 1024 || sha256(JSON.stringify(snapshot.files)) !== snapshot.sha256) return invalid();
    if (snapshot.root_identity !== undefined) {
      const root = object(snapshot.root_identity); if (!root || root.device !== identity.device || root.inode !== identity.inode) return invalid();
    }
    if (snapshot.source_map !== undefined && (!Array.isArray(snapshot.source_map) || snapshot.source_map.length > 10_128 || snapshot.source_map.some(entry => {
      const source = object(entry); return !source || typeof source.snapshot_path !== 'string' || !validPortablePath(source.snapshot_path) || typeof source.original_path !== 'string' || (!path.isAbsolute(source.original_path) && !source.original_path.startsWith('ud://'));
    }))) return invalid();
  }
  if (record.validation !== undefined) {
    const validation = object(record.validation); if (!validation || typeof validation.completed !== 'boolean' || typeof validation.passed !== 'boolean') return invalid();
  }
  if (record.plan_completion !== undefined) completedPlanBatch(record.plan_completion);
  if (record.plan_dependencies !== undefined) {
    if (!Array.isArray(record.plan_dependencies) || record.plan_dependencies.length > 1000) return invalid();
    for (const batch of record.plan_dependencies) completedPlanBatch(batch);
  }
  return record as RecordV1;
}
export function editRequestKey(operation: string, args: Record<string, unknown>): string {
  const options = object(args.edit_options) ?? object(args.options) ?? {};
  if (options.idempotency_key !== undefined && (typeof options.idempotency_key !== 'string' || options.idempotency_key.length < 1 || options.idempotency_key.length > 256)) throw new Error('Invalid edit idempotency key.');
  // Preserve the original transaction identifier for requests without an
  // explicit key, including journals written before request records existed.
  return options.idempotency_key as string | undefined ?? sha256(JSON.stringify({ operation, arguments: args }));
}

export async function verifyDependencyContexts(batches: readonly CompletedPlanBatch[], resources?: ResourceStore): Promise<void> {
  for (const batch of batches) for (const reference of batch.contexts) {
    if (!resources) throw new Error('PLAN_COMPLETION_CONTEXT_UNAVAILABLE');
    try {
      const bytes = await resources.bytes(reference.uri, 'contexts'), value = object(JSON.parse(bytes.toString('utf8')));
      if (sha256(bytes) !== reference.sha256 || !value || typeof value.manifest !== 'string' || object(JSON.parse(value.manifest))?.context_sha256 !== reference.context_sha256) throw new Error('PLAN_COMPLETION_CONTEXT_CHANGED');
    } catch (error) { throw new Error('PLAN_COMPLETION_STALE: context publication is unavailable or changed.', { cause: error }); }
  }
}
async function verifyBatchState(batch: CompletedPlanBatch, workspace: GuardedWorkspace, resources?: ResourceStore): Promise<void> {
  for (const output of batch.outputs) {
    const bytes = await workspace.readOptional(output.path);
    if ((bytes === null ? null : sha256(bytes)) !== output.sha256) throw new Error('PLAN_COMPLETION_STALE: output changed.');
  }
  await verifyDependencyContexts([batch], resources);
}

/** Read-only admission; legacy records without explicit host issuance are ignored. */
export async function loadCompletedPlanBatches(input: { args: Record<string, unknown>; guard: string; grants: readonly string[]; stateRoot: string; resources: ResourceStore; signal?: AbortSignal }): Promise<CompletedPlanBatch[]> {
  const cancelled = () => { if (input.signal?.aborted) throw new Error('WORKER_CANCELLED'); }; cancelled();
  if (typeof input.args.working_tree_path !== 'string' || typeof input.args.plan_path !== 'string') return [];
  const workspace = await GuardedWorkspace.open(input.args.working_tree_path, input.guard, input.grants);
  const absolute = path.resolve(workspace.root, input.args.plan_path), relative = path.relative(workspace.root, absolute);
  const local = relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
  const source = local ? workspace : await GuardedWorkspace.open(path.dirname(absolute), input.guard, input.grants);
  const bytes = await source.read(local ? relative.split(path.sep).join('/') : path.basename(absolute));
  const planSha256 = sha256(bytes), selection = planSelection(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)), []);
  let store: JournalStore;
  try { store = await JournalStore.readOnly(input.stateRoot, input.guard); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
  const native = await openStateAuthority(input.stateRoot, input.guard), names = (await readdir(input.stateRoot)).filter(name => /^\.request-[0-9a-f]{64}\.json$/.test(name)).sort();
  if (names.length > 1000) throw new Error('PLAN_COMPLETION_SCAN_LIMIT');
  let total = 0; const admitted: CompletedPlanBatch[] = [];
  for (const name of names) {
    cancelled();
    const raw = await boundedRead(path.join(input.stateRoot, name), 64 * 1024 * 1024, native); total += raw.length;
    if (total > 128 * 1024 * 1024) throw new Error('PLAN_COMPLETION_SCAN_LIMIT');
    const record = recoveryRecord(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(raw)));
    if (!record.plan_completion || record.workspace !== workspace.root || record.operation !== 'plan_apply') continue;
    const batch = completedPlanBatch(record.plan_completion);
    if (batch.plan_sha256 !== planSha256) continue;
    if (record.identity.device !== workspace.identity.device || record.identity.inode !== workspace.identity.inode || batch.workspace !== workspace.root || batch.identity.device !== workspace.identity.device || batch.identity.inode !== workspace.identity.inode || !record.snapshot || batch.snapshot_sha256 !== record.snapshot.sha256 || record.snapshot.files.find(file => file.path === batch.plan_path)?.sha256 !== planSha256 || batch.action_ids.some(id => !selection.actions.has(id)) || batch.actions_sha256 !== actionSetHash(selection.actions, batch.action_ids) || planCanonical(object(record.result?.details)?.selected_action_ids) !== planCanonical(batch.action_ids)) throw new Error('PLAN_COMPLETION_INVALID');
    const journal = batch.transaction_id === null ? undefined : await store.load(batch.transaction_id);
    if (batch.transaction_id !== null && (name !== `.request-${batch.transaction_id}.json` || !journal || journal.phase !== 'completed' || journal.workspace !== workspace.root || journal.identity.device !== workspace.identity.device || journal.identity.inode !== workspace.identity.inode || journal.request_hash !== batch.request_hash || journal.request_hash !== transactionRequestHash(journal.workspace, journal.identity, journal.entries, journal.read_preconditions) || record.validation?.completed !== true || record.validation.passed !== true || planCanonical(journal.entries.map(entry => ({ path: entry.path, sha256: entry.after }))) !== planCanonical(batch.outputs))) throw new Error('PLAN_COMPLETION_INVALID');
    const contextActions = batch.action_ids.filter(id => selection.actions.get(id)?.type === 'prepare_context');
    if (batch.validation === 'context-publication' && contextActions.length !== batch.action_ids.length) throw new Error('PLAN_COMPLETION_INVALID');
    if (contextActions.length !== batch.contexts.length || contextActions.some(id => !batch.contexts.some(reference => reference.action_id === id))) throw new Error('PLAN_COMPLETION_INVALID');
    try {
      await verifyBatchState(batch, workspace, input.resources);
      const outputs = new Map(batch.outputs.map(item => [item.path, item.sha256]));
      for (const file of record.snapshot.files.filter(file => !file.path.startsWith('.ud-agent-inputs/'))) {
        const current = await workspace.readOptional(file.path), expected = outputs.has(file.path) ? outputs.get(file.path)! : file.sha256;
        if ((current === null ? null : sha256(current)) !== expected) throw new Error('PLAN_COMPLETION_STALE');
      }
      for (const condition of journal?.read_preconditions ?? []) {
        const current = await workspace.readOptional(condition.path), expected = outputs.has(condition.path) ? outputs.get(condition.path)! : condition.sha256;
        if ((current === null ? null : sha256(current)) !== expected) throw new Error('PLAN_COMPLETION_STALE');
      }
    } catch (error) { if (error instanceof Error && error.message.startsWith('PLAN_COMPLETION_STALE')) continue; throw error; }
    for (const reference of batch.contexts) await verifyPublishedPlanContext(selection.actions.get(reference.action_id)!, reference, input.resources);
    cancelled();
    admitted.push(batch);
  }
  cancelled(); return admitted;
}

/** Durable worker intent precedes apply; a retry recovers before rerunning code. */
export class MutationRecovery {
  private constructor(private readonly file: string, readonly key: string, private readonly id: string, private readonly guard: string, private readonly workspace: GuardedWorkspace, private readonly grants: readonly string[], private readonly store: JournalStore, private readonly native: NativeState | undefined, private record: RecordV1, readonly release: () => Promise<void>, private readonly resources?: ResourceStore) {}
  static async open(input: { operation: string; args: Record<string, unknown>; guard: string; grants: readonly string[]; stateRoot: string; provenance: Record<string, unknown>; resources?: ResourceStore }): Promise<MutationRecovery | undefined> {
    const options = object(input.args.edit_options) ?? object(input.args.options) ?? {};
    if (options.mode !== 'apply') return undefined;
    if (typeof input.args.working_tree_path !== 'string') throw new Error('A granted working tree is required.');
    const workspace = await GuardedWorkspace.open(input.args.working_tree_path, input.guard, input.grants);
    const key = editRequestKey(input.operation, input.args), id = sha256(`${workspace.root}\0${key}`);
    await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
    const store = await JournalStore.open(input.stateRoot, input.guard), native = await openStateAuthority(store.root, input.guard);
    const release = await guardedStateLock(input.guard, store.root, `.request-${id}.native`, await guardedIdentity(input.guard, store.root));
    const file = path.join(store.root, `.request-${id}.json`), requestHash = sha256(canonical({ operation: input.operation, arguments: { ...input.args, working_tree_path: workspace.root } }));
    try {
      let record: RecordV1;
      try {
        try { record = recoveryRecord(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await boundedRead(file, 64 * 1024 * 1024, native)))); }
        catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw error; throw new Error('EDIT_RECOVERY_RECORD_INVALID', { cause: error }); }
        if (record.version !== 1 || record.operation !== input.operation || record.request_hash !== requestHash || record.workspace !== workspace.root || record.identity?.device !== workspace.identity.device || record.identity?.inode !== workspace.identity.inode) throw new Error('IDEMPOTENCY_KEY_REUSED_OR_WORKSPACE_CHANGED');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        record = { version: 1, operation: input.operation, request_hash: requestHash, workspace: workspace.root, identity: workspace.identity, provenance: input.provenance };
        await durableWrite(file, Buffer.from(JSON.stringify(record)), native);
      }
      return new MutationRecovery(file, key, id, input.guard, workspace, input.grants, store, native, record, release, input.resources);
    } catch (error) { await release(); throw error; }
  }
  private async save(): Promise<void> {
    const bytes = Buffer.from(JSON.stringify(this.record)); if (bytes.length > 64 * 1024 * 1024) throw new Error('EDIT_RECOVERY_RECORD_TOO_LARGE');
    await durableWrite(this.file, bytes, this.native);
  }
  async remember(result: Record<string, unknown>, snapshot: Snapshot, dependencies?: CompletedPlanBatch[]): Promise<void> {
    this.record = recoveryRecord({ ...this.record, result, snapshot, validation: undefined, plan_completion: undefined, ...(dependencies?.length ? { plan_dependencies: dependencies } : {}) }); await this.save();
  }
  async completePlan(batch: CompletedPlanBatch, result: Record<string, unknown>): Promise<void> {
    batch = completedPlanBatch(batch);
    if (this.record.operation !== 'plan_apply' || batch.workspace !== this.workspace.root || batch.identity.device !== this.workspace.identity.device || batch.identity.inode !== this.workspace.identity.inode || batch.snapshot_sha256 !== this.record.snapshot?.sha256 || this.record.snapshot.files.find(file => file.path === batch.plan_path)?.sha256 !== batch.plan_sha256) throw new Error('PLAN_COMPLETION_INVALID');
    if (batch.transaction_id !== null) {
      const journal = await this.store.load(this.id);
      if (batch.transaction_id !== this.id || !journal || journal.phase !== 'completed' || journal.request_hash !== batch.request_hash || journal.request_hash !== transactionRequestHash(journal.workspace, journal.identity, journal.entries, journal.read_preconditions) || journal.workspace !== batch.workspace || journal.identity.device !== batch.identity.device || journal.identity.inode !== batch.identity.inode || this.record.validation?.completed !== true || this.record.validation.passed !== true || planCanonical(journal.entries.map(entry => ({ path: entry.path, sha256: entry.after }))) !== planCanonical(batch.outputs)) throw new Error('PLAN_COMPLETION_INVALID');
    }
    await verifyBatchState(batch, this.workspace, this.resources);
    const outputs = new Map(batch.outputs.map(item => [item.path, item.sha256]));
    for (const file of this.record.snapshot.files.filter(item => !item.path.startsWith('.ud-agent-inputs/'))) {
      const current = await this.workspace.readOptional(file.path), expected = outputs.has(file.path) ? outputs.get(file.path)! : file.sha256;
      if ((current === null ? null : sha256(current)) !== expected) throw new Error('PLAN_COMPLETION_STALE');
    }
    this.record.plan_completion = batch; this.record.result = result; await this.save();
  }
  async validated(value: { completed: boolean; passed: boolean; details?: unknown }): Promise<void> { this.record.validation = value; await this.save(); }
  async replay(): Promise<{ result: Record<string, unknown>; snapshot?: Snapshot; provenance: Record<string, unknown> } | undefined> {
    const journal = await this.store.load(this.id);
    if (!journal) {
      if (!this.record.plan_completion || this.record.plan_completion.transaction_id !== null || !this.record.result) return undefined;
      await verifyBatchState(this.record.plan_completion, this.workspace, this.resources);
      for (const file of this.record.snapshot?.files.filter(item => !item.path.startsWith('.ud-agent-inputs/')) ?? []) {
        const current = await this.workspace.readOptional(file.path); if ((current === null ? null : sha256(current)) !== file.sha256) throw new Error('IDEMPOTENT_RESULT_STALE');
      }
      return { result: { ...this.record.result, replayed: true }, ...(this.record.snapshot ? { snapshot: this.record.snapshot } : {}), provenance: this.record.provenance };
    }
    if (journal.phase === 'completed') await verifyDependencyContexts(this.record.plan_dependencies ?? [], this.resources);
    const outcome = await new TransactionBroker(this.store, this.workspace, () => verifyDependencyContexts(this.record.plan_dependencies ?? [], this.resources)).recover(this.id);
    if (!this.record.result || !this.record.snapshot) return { result: { status: 'incomplete', code: 'LEGACY_TRANSACTION_RECOVERED', reason: 'The prior transaction was reconciled; its older state did not retain the original worker report.', transaction: outcome }, provenance: { recovery: 'legacy_transaction_journal' } };
    if (outcome.status !== 'completed') return { result: { ...this.record.result, status: 'incomplete', code: outcome.status === 'rolled_back' ? 'TRANSACTION_ROLLED_BACK' : 'TRANSACTION_CONFLICT', reason: outcome.message ?? 'The interrupted transaction was reconciled without claiming a completed edit.', requires_host_commit: false, transaction: outcome, replayed: true }, snapshot: this.record.snapshot, provenance: this.record.provenance };
    if (this.record.validation?.completed !== true || this.record.validation.passed !== true) throw new Error('EDIT_RECOVERY_VALIDATION_EVIDENCE_MISSING');
    const outputs = new Map(outcome.files.map(file => [file.path, file.after_sha256]));
    for (const file of this.record.snapshot.files.filter(file => !file.path.startsWith('.ud-agent-inputs/'))) {
      const expected = outputs.has(file.path) ? outputs.get(file.path)! : file.sha256;
      const current = await this.workspace.readOptional(file.path);
      if ((current === null ? null : sha256(current)) !== expected) throw new Error('IDEMPOTENT_RESULT_STALE');
    }
    for (const [file, expected] of outputs) {
      const current = await this.workspace.readOptional(file); if ((current === null ? null : sha256(current)) !== expected) throw new Error('IDEMPOTENT_RESULT_STALE');
    }
    for (const condition of journal.read_preconditions ?? []) {
      const expected = outputs.has(condition.path) ? outputs.get(condition.path)! : condition.sha256;
      const current = await this.workspace.readOptional(condition.path);
      if ((current === null ? null : sha256(current)) !== expected) throw new Error('IDEMPOTENT_RESULT_STALE');
    }
    // Recheck external inputs under the current grants; a prior report never
    // grants access to an input that this session cannot authorize.
    for (const file of this.record.snapshot.files.filter(file => file.path.startsWith('.ud-agent-inputs/'))) {
      const source = this.record.snapshot.source_map?.find(item => item.snapshot_path === file.path)?.original_path;
      if (!source || source.startsWith('ud://')) continue;
      const external = await GuardedWorkspace.open(path.dirname(source), this.guard, this.grants);
      const bytes = await external.read(path.basename(source)); if (sha256(bytes) !== file.sha256) throw new Error('IDEMPOTENT_RESULT_STALE');
    }
    return { result: { ...this.record.result, requires_host_commit: false, transaction: { ...outcome, candidate_validation: this.record.validation }, validation: { status: 'completed', passed: true }, replayed: true }, snapshot: this.record.snapshot, provenance: this.record.provenance };
  }
}
