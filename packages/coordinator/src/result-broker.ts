import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { JournalStore, sha256 } from '../../workspace/src/journal.js';
import { GuardedWorkspace, TransactionBroker } from '../../workspace/src/transactions.js';
import type { Candidate } from '../../workspace/src/transactions.js';
import { handleWorkerCandidates, normalizeWorkerCandidates } from '../../workspace/src/worker-candidates.js';
import { operationInputPaths } from '../../workspace/src/snapshot.js';
import type { SnapshotFile } from '../../workspace/src/snapshot.js';
import type { Snapshot } from '../../workspace/src/snapshot.js';
import { captureOperationSnapshot } from '../../workspace/src/input-broker.js';
import type { ContextBundle } from '../../workspace/src/input-broker.js';
import { guardedRead } from '../../workspace/src/guard.js';
import { editRequestKey } from './mutation-recovery.js';
import { planActionPaths, verifiedPlanConditions } from '../../workspace/src/plan-state.js';
import { actionSetHash, completedPlanBatch } from '../../workspace/src/plan-completions.js';
import type { CompletedPlanBatch } from '../../workspace/src/plan-completions.js';

type Validation = { completed: boolean; passed: boolean; details?: unknown };
type Input = {
  operation: string; args: Record<string, unknown>; result: Record<string, unknown>;
  snapshot: { root_identity?: { device: string; inode: string }; sha256: string; files: SnapshotFile[] }; guard: string; allowedRoots: readonly string[];
  stateRoot: string; signal?: AbortSignal;
  installedContext?: string; contextBundle?: ContextBundle;
  remember?: (result: Record<string, unknown>, snapshot: Input['snapshot'], dependencies?: CompletedPlanBatch[]) => Promise<void>;
  recordValidation?: (validation: Validation) => Promise<void>;
  completePlan?: (batch: CompletedPlanBatch, result: Record<string, unknown>) => Promise<void>;
  verifyDependencies?: (batches: readonly CompletedPlanBatch[]) => Promise<void>;
  validate: (workingTree: string, files: string[], contextPath?: string) => Promise<Validation>;
};
function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }

/** Derive write scope from user-selected inputs, never from worker output. */
async function writeScope(input: Input, args: Record<string, unknown>, snapshot: Snapshot): Promise<Set<string>> {
  const paths = operationInputPaths(args).filter(name => !name.startsWith('.ud-agent-inputs/'));
  const scoped = new Set(input.operation === 'plan_apply' ? [] : input.snapshot.files.filter(file => paths.length === 0 || paths.some(selected => file.path === selected || file.path.startsWith(`${selected}/`))).map(file => file.path));
  if (input.operation === 'treebank_create') {
    const template = args.template_path;
    if (typeof template === 'string') {
      for (const file of input.snapshot.files) if (file.path.startsWith(`${template}/`)) scoped.add(file.path.slice(template.length + 1));
    } else { scoped.add('README.md'); scoped.add('CONTRIBUTING.md'); }
  }
  if (input.operation === 'plan_apply' && typeof args.plan_path === 'string') {
    const plan = object(JSON.parse((await guardedRead(input.guard, snapshot.directory, args.plan_path, 64 * 1024 * 1024, snapshot.snapshot_identity, input.signal)).toString('utf8')));
    const selected = input.args.selected_action_ids;
    if (!plan || !Array.isArray(plan.actions) || !Array.isArray(selected)) throw new Error('Invalid constrained plan scope.');
    for (const action of plan.actions) {
      const item = object(action);
      if (!item || !selected.includes(item.id)) continue;
      for (const name of planActionPaths(item)) scoped.add(name);
    }
  }
  return scoped;
}

/** Independently validate exact candidate bytes in disposable staged storage. */
async function validateCandidates(input: Input, candidates: readonly Candidate[], snapshot: Snapshot, contextPath?: string): Promise<Validation> {
  const root = input.args.working_tree_path;
  if (typeof root !== 'string') throw new Error('A granted working tree is required.');
    if (snapshot.sha256 !== input.snapshot.sha256) throw new Error('WORKTREE_CHANGED_BEFORE_CANDIDATE_VALIDATION');
    const known = new Map(snapshot.files.map(file => [file.path, file.sha256]));
    for (const candidate of candidates) {
      if ((known.get(candidate.path) ?? null) !== candidate.before_sha256) throw new Error('CANDIDATE_SOURCE_MISMATCH');
      const target = path.join(snapshot.directory, ...candidate.path.split('/'));
      if (candidate.after_base64 === null) { await rm(target); known.delete(candidate.path); }
      else {
        await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
        const bytes = Buffer.from(candidate.after_base64, 'base64');
        await writeFile(target, bytes, { mode: 0o600 }); known.set(candidate.path, sha256(bytes));
      }
    }
    const files = [...known.keys()].filter(name => name.endsWith('.conllu') && !name.startsWith('.ud-agent-inputs/')).sort();
    if (files.length === 0) return { completed: true, passed: true, details: { scope: 'non-corpus-output', byte_hashes_verified: true } };
    return await input.validate(snapshot.directory, files, contextPath === undefined ? undefined : path.join(snapshot.directory, ...contextPath.split('/')));
}

/** Worker intent becomes host mutation only through an independently checked transaction. */
export async function brokerWorkerResult(input: Input): Promise<Record<string, unknown>> {
  if (input.result.status !== 'candidate') return input.result;
  if ((input.result.requires_host_export === true || input.result.requires_broker_export === true) && input.result.changes === undefined && input.result.file_operations === undefined) return input.result;
  const root = input.args.working_tree_path;
  if (typeof root !== 'string') throw new Error('A granted working tree is required.');
  const edit = object(input.args.edit_options) ?? object(input.args.options) ?? {};
  const mode = edit.mode ?? 'preview';
  if (mode !== 'preview' && mode !== 'apply') throw new Error('Edit mode must be preview or apply.');
  const workspace = await GuardedWorkspace.open(root, input.guard, input.allowedRoots);
  if (input.snapshot.root_identity && (workspace.identity.device !== input.snapshot.root_identity.device || workspace.identity.inode !== input.snapshot.root_identity.inode)) throw new Error('WORKSPACE_IDENTITY_CHANGED');
  const captured = await captureOperationSnapshot(input.guard, input.args, input.allowedRoots, input.signal, input.installedContext, input.operation, input.contextBundle);
  try {
  if (captured.snapshot.root_identity.device !== workspace.identity.device || captured.snapshot.root_identity.inode !== workspace.identity.inode) throw new Error('WORKSPACE_IDENTITY_CHANGED');
  if (captured.snapshot.sha256 !== input.snapshot.sha256) throw new Error('WORKTREE_CHANGED_BEFORE_CANDIDATE_VALIDATION');
  const allowedPaths = await writeScope(input, captured.arguments, captured.snapshot);
  const operations = Array.isArray(input.result.file_operations) ? await Promise.all(input.result.file_operations.map(async value => {
    const item = object(value);
    if (!item || item.operation !== 'rename' || typeof item.file_path !== 'string') return value;
    if (!allowedPaths.has(item.file_path)) throw new Error('Rename source is outside the selected scope.');
    const bytes = await workspace.read(item.file_path);
    if (sha256(bytes) !== item.before_sha256) throw new Error('STALE_PRECONDITION');
    return { ...item, after_sha256: item.before_sha256, content: undefined, content_base64: bytes.toString('base64') };
  })) : [];
  const result: Record<string, unknown> = { ...input.result, requested_mode: mode, file_operations: operations };
  const candidates = normalizeWorkerCandidates(result, allowedPaths, mode);
  const planProof = input.operation === 'plan_apply' ? await verifiedPlanConditions(input.guard, captured.arguments, captured.snapshot, candidates, input.signal) : undefined;
  if (planProof) {
    const details = { ...object(result.details), selected_action_ids: planProof.selection.selected };
    delete (details as Record<string, unknown>).satisfied_action_ids;
    result.details = { ...details, ...(planProof.selection.satisfied.length ? { satisfied_action_ids: planProof.selection.satisfied } : {}) };
  }
  if (mode === 'apply') await input.remember?.(result, input.snapshot, planProof?.batches);
  await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
  const store = await JournalStore.open(input.stateRoot, input.guard);
  const broker = new TransactionBroker(store, workspace, () => input.verifyDependencies?.(planProof?.batches ?? []) ?? Promise.resolve());
  const validate = (values: readonly Candidate[]) => validateCandidates(input, values, captured.snapshot, captured.contextPath);
  const key = editRequestKey(input.operation, input.args);
  const transaction = await handleWorkerCandidates({ result, allowedPaths, mode, broker, idempotencyKey: key, validate, ...(planProof ? { readPreconditions: planProof.conditions } : {}), ...(input.recordValidation ? { validationRecorder: input.recordValidation } : {}), ...(input.signal ? { signal: input.signal } : {}) });
  const independent = transaction.candidate_validation as Validation | undefined;
  const finalResult = { ...result, ...(independent ? { validation: { status: independent.completed ? 'completed' : 'incomplete', passed: independent.passed } } : {}), requires_host_commit: mode === 'apply' ? false : result.requires_host_commit, transaction };
  if (planProof && mode === 'apply' && transaction.status === 'completed' && input.completePlan && typeof captured.arguments.plan_path === 'string') {
    const references = Array.isArray(result.prepared_contexts) ? result.prepared_contexts.map(value => {
      const item = object(value); if (!item || typeof item.action_id !== 'string' || typeof item.uri !== 'string' || typeof item.sha256 !== 'string' || typeof item.context_sha256 !== 'string') throw new Error('PLAN_COMPLETION_INVALID');
      return { action_id: item.action_id, uri: item.uri, sha256: item.sha256, context_sha256: item.context_sha256 };
    }) : [];
    const journal = transaction.transaction_id ? await store.load(transaction.transaction_id) : undefined;
    const contextOnly = planProof.selection.selected.every(id => planProof.selection.actions.get(id)?.type === 'prepare_context');
    if (transaction.files.length || references.length && contextOnly) await input.completePlan(completedPlanBatch({ schema_version: 1, workspace: workspace.root, identity: workspace.identity, plan_path: captured.arguments.plan_path, plan_sha256: planProof.planSha256, action_ids: planProof.selection.selected, actions_sha256: actionSetHash(planProof.selection.actions, planProof.selection.selected), snapshot_sha256: input.snapshot.sha256, transaction_id: journal?.id ?? null, request_hash: journal?.request_hash ?? null, outputs: transaction.files.map(file => ({ path: file.path, sha256: file.after_sha256 })), contexts: references, validation: journal ? 'passed' : 'context-publication' }), finalResult);
  }
  return finalResult;
  } finally { await captured.snapshot.cleanup(); }
}
