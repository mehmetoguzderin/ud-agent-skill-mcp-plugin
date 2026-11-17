/** Transport-owned observations used to prove already-satisfied plan dependencies. */
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { guardedRead, guardedReadOptional } from './guard.js';
import { sha256 } from './journal.js';
import { portablePathKey, validPortablePath } from './portable-path.js';
import { operationInputPaths } from './snapshot.js';
import type { Snapshot } from './snapshot.js';
import type { Candidate } from './transactions.js';
import { actionSetHash, currentCompletedPlanBatches } from './plan-completions.js';
import type { CompletedPlanBatch } from './plan-completions.js';

export const PLAN_STATE_PATH = '.ud-agent-inputs/plan-state/manifest.json';
export type FileCondition = { path: string; sha256: string | null };
type Action = Record<string, unknown>;
export type PlanSelection = { actions: Map<string, Action>; selected: string[]; ordered: string[]; satisfied: string[] };
const HASH = /^[0-9a-f]{64}$/;
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function name(value: unknown): string {
  if (typeof value !== 'string' || !validPortablePath(value) || value === '.ud-agent-inputs' || value.startsWith('.ud-agent-inputs/')) throw new Error('PLAN_STATE_PATH_INVALID');
  return value;
}
function hash(value: unknown): string { if (typeof value !== 'string' || !HASH.test(value)) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE'); return value; }
function content(action: Action): string {
  if (typeof action.content !== 'string' || Buffer.byteLength(action.content) > 64 * 1024 * 1024 || Buffer.from(action.content).toString('utf8') !== action.content || sha256(action.content) !== hash(action.after_sha256)) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
  return action.after_sha256 as string;
}

export function planActionPaths(action: Action): string[] {
  if (action.type === 'rename_file') {
    if (action.file_path !== undefined && action.source !== undefined && action.file_path !== action.source || action.target_file_path !== undefined && action.destination !== undefined && action.target_file_path !== action.destination) throw new Error('PLAN_RENAME_ALIASES_CONFLICT');
    const source = name(action.file_path ?? action.source), target = name(action.target_file_path ?? action.destination);
    if (portablePathKey(source) === portablePathKey(target)) throw new Error('PLAN_RENAME_ALIASES_CONFLICT');
    return [source, target];
  }
  return [...(action.file_path === undefined ? [] : [name(action.file_path)]), ...(object(action.arguments) ? operationInputPaths(action.arguments).map(name) : [])];
}

/** Traverse the entire requested closure, while keeping execution selection separate. */
export function planSelection(value: unknown, selected: unknown): PlanSelection {
  if (!object(value) || value.schema_version !== 'ud-plan-v1' || !Array.isArray(value.actions) || value.actions.length > 1000 || !Array.isArray(selected) || selected.length > 1000 || selected.some(id => typeof id !== 'string') || new Set(selected).size !== selected.length) throw new Error('PLAN_SELECTION_INVALID');
  const actions = new Map<string, Action>();
  for (const action of value.actions) {
    if (!object(action) || typeof action.id !== 'string' || !action.id || action.id.length > 4096 || actions.has(action.id)) throw new Error('PLAN_ACTION_ID_INVALID');
    if (action.type === 'rename_file') planActionPaths(action);
    actions.set(action.id, action);
  }
  const states = new Map<string, number>(), ordered: string[] = [];
  for (const id of selected as string[]) {
    const stack: [string, boolean][] = [[id, false]];
    while (stack.length) {
      const [current, done] = stack.pop()!;
      if (done) { states.set(current, 2); ordered.push(current); continue; }
      if (states.get(current) === 2) continue;
      if (states.get(current) === 1) throw new Error('PLAN_DEPENDENCY_CYCLE');
      const action = actions.get(current);
      if (!action || !Array.isArray(action.depends_on) || action.depends_on.length > 1000 || action.depends_on.some(item => typeof item !== 'string' || !actions.has(item))) throw new Error('PLAN_DEPENDENCY_MISSING');
      states.set(current, 1); stack.push([current, true]);
      for (const dependency of [...action.depends_on].reverse() as string[]) stack.push([dependency, false]);
    }
  }
  const selectedSet = new Set(selected as string[]);
  return { actions, selected: [...selected] as string[], ordered: ordered.filter(id => selectedSet.has(id)), satisfied: ordered.filter(id => !selectedSet.has(id)) };
}

/** Explicit complete file states; no annotation inference or prior-result adoption. */
export function actionPostconditions(action: Action): FileCondition[] {
  const kind = action.type;
  const fields: Record<string, string[]> = {
    create_file: ['file_path', 'before_sha256', 'after_sha256', 'content'],
    replace_file: ['file_path', 'before_sha256', 'after_sha256', 'content', 'diff'],
    delete_file: ['file_path', 'before_sha256', 'after_sha256'],
    rename_file: ['file_path', 'source', 'target_file_path', 'destination', 'before_sha256', 'target_before_sha256', 'content', 'after_sha256', 'conflict'],
  };
  if (typeof kind !== 'string' || !Object.hasOwn(fields, kind) || Object.keys(action).some(key => !['id', 'type', 'depends_on', 'input_fingerprints', ...fields[kind]!].includes(key))) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
  if (action.input_fingerprints !== undefined) {
    if (!object(action.input_fingerprints)) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
    for (const [key, value] of Object.entries(action.input_fingerprints)) { name(key); hash(value); }
  }
  let result: FileCondition[];
  if (kind === 'replace_file' || kind === 'create_file') {
    if (kind === 'create_file' && action.before_sha256 !== null) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
    if (kind === 'replace_file') hash(action.before_sha256);
    result = [{ path: name(action.file_path), sha256: content(action) }];
  } else if (kind === 'delete_file') {
    hash(action.before_sha256); if (action.after_sha256 !== null) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
    result = [{ path: name(action.file_path), sha256: null }];
  } else if (kind === 'rename_file') {
    const [source, target] = planActionPaths(action) as [string, string], before = hash(action.before_sha256);
    if (portablePathKey(source) === portablePathKey(target) || action.target_before_sha256 !== null || action.conflict !== undefined && action.conflict !== false) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
    const after = action.content === undefined ? before : content(action);
    if (action.after_sha256 !== undefined && action.after_sha256 !== after) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
    result = [{ path: source, sha256: null }, { path: target, sha256: after }];
  } else throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
  if (action.postconditions !== undefined) throw new Error('PLAN_DEPENDENCY_POSTCONDITION_UNPROVABLE');
  return result;
}

export function dependencyConditions(selection: PlanSelection, batches: readonly CompletedPlanBatch[] = []): FileCondition[] {
  const conditions = new Map<string, FileCondition>();
  for (const id of selection.satisfied) for (const item of batches.find(batch => batch.action_ids.includes(id))?.outputs ?? actionPostconditions(selection.actions.get(id)!)) {
    const key = portablePathKey(item.path), previous = conditions.get(key);
    if (previous && (previous.path !== item.path || previous.sha256 !== item.sha256)) throw new Error('PLAN_DEPENDENCY_POSTCONDITIONS_CONFLICT');
    conditions.set(key, item);
  }
  return [...conditions.values()].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

function matchingBatches(root: string, snapshot: Snapshot, planPath: string, planSha256: string, selection: PlanSelection): CompletedPlanBatch[] {
  return currentCompletedPlanBatches().filter(batch => batch.workspace === root && batch.identity.device === snapshot.root_identity.device && batch.identity.inode === snapshot.root_identity.inode && batch.plan_path === planPath && batch.plan_sha256 === planSha256 && batch.action_ids.every(id => selection.actions.has(id)) && batch.actions_sha256 === actionSetHash(selection.actions, batch.action_ids) && selection.satisfied.some(id => batch.action_ids.includes(id)));
}

export async function appendPlanState(guard: string, root: string, args: Record<string, unknown>, snapshot: Snapshot, signal?: AbortSignal): Promise<Record<string, unknown>> {
  if (typeof args.plan_path !== 'string') throw new Error('PLAN_PATH_INVALID');
  const planBytes = await guardedRead(guard, snapshot.directory, args.plan_path, 16 * 1024 * 1024, snapshot.snapshot_identity, signal);
  const selection = planSelection(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(planBytes)), args.selected_action_ids);
  const batches = matchingBatches(root, snapshot, args.plan_path, sha256(planBytes), selection);
  const conditions = dependencyConditions(selection, batches), names = new Map<string, string>();
  const add = (value: unknown) => { const item = name(value), key = portablePathKey(item), previous = names.get(key); if (previous && previous !== item) throw new Error('PLAN_STATE_PATH_COLLISION'); names.set(key, item); };
  for (const item of conditions) add(item.path);
  for (const id of selection.ordered) {
    const action = selection.actions.get(id)!;
    for (const item of planActionPaths(action)) add(item);
    if (object(action.input_fingerprints)) for (const key of Object.keys(action.input_fingerprints)) add(key);
  }
  if (names.size > 10000) throw new Error('PLAN_STATE_LIMIT');
  const states: FileCondition[] = [];
  let total = snapshot.files.reduce((sum, item) => sum + item.size, 0);
  for (const item of [...names.values()].sort()) {
    if (signal?.aborted) throw new Error('WORKER_CANCELLED');
    const first = await guardedReadOptional(guard, root, item, snapshot.root_identity), fingerprint = first === null ? null : sha256(first);
    const existing = snapshot.files.find(file => portablePathKey(file.path) === portablePathKey(item));
    if (existing && (existing.path !== item || existing.sha256 !== fingerprint)) throw new Error('PLAN_STATE_CHANGED_DURING_CAPTURE');
    if (first !== null && !existing) {
      total += first.length;
      if (snapshot.files.length >= 10000 || total > 512 * 1024 * 1024) throw new Error('PLAN_STATE_LIMIT');
      const target = path.join(snapshot.directory, ...item.split('/')); await mkdir(path.dirname(target), { recursive: true, mode: 0o700 }); await writeFile(target, first, { flag: 'wx', mode: 0o600 });
      snapshot.files.push({ path: item, sha256: fingerprint!, size: first.length });
    }
    const second = await guardedReadOptional(guard, root, item, snapshot.root_identity);
    if (signal?.aborted) throw new Error('WORKER_CANCELLED');
    if ((second === null ? null : sha256(second)) !== fingerprint) throw new Error('PLAN_STATE_CHANGED_DURING_CAPTURE');
    states.push({ path: item, sha256: fingerprint });
  }
  for (const condition of conditions) if (states.find(item => item.path === condition.path)?.sha256 !== condition.sha256) throw new Error(`PLAN_DEPENDENCY_NOT_SATISFIED: ${condition.path}`);
  const bytes = Buffer.from(JSON.stringify({ schema_version: 1, plan_path: args.plan_path, plan_sha256: sha256(planBytes), selected_action_ids: selection.selected, satisfied_action_ids: selection.satisfied, states, ...(batches.length ? { completed_batches: batches } : {}) }));
  if (bytes.length > 1024 * 1024) throw new Error('PLAN_STATE_LIMIT');
  await mkdir(path.join(snapshot.directory, path.posix.dirname(PLAN_STATE_PATH)), { recursive: true, mode: 0o700 });
  await writeFile(path.join(snapshot.directory, PLAN_STATE_PATH), bytes, { flag: 'wx', mode: 0o600 });
  snapshot.files.push({ path: PLAN_STATE_PATH, size: bytes.length, sha256: sha256(bytes) });
  return { manifest_path: PLAN_STATE_PATH, sha256: sha256(bytes) };
}

/** Host re-derives postconditions from the frozen plan, never worker details. */
export async function verifiedPlanConditions(guard: string, args: Record<string, unknown>, snapshot: Snapshot, candidates: readonly Candidate[], signal?: AbortSignal): Promise<{ conditions: FileCondition[]; selection: PlanSelection; batches: CompletedPlanBatch[]; planSha256: string }> {
  if (typeof args.plan_path !== 'string') throw new Error('PLAN_PATH_INVALID');
  const bytes = await guardedRead(guard, snapshot.directory, args.plan_path, 16 * 1024 * 1024, snapshot.snapshot_identity, signal);
  const selection = planSelection(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)), args.selected_action_ids);
  const batches = matchingBatches(args.working_tree_path as string, snapshot, args.plan_path, sha256(bytes), selection);
  const raw = await guardedRead(guard, snapshot.directory, PLAN_STATE_PATH, 1024 * 1024, snapshot.snapshot_identity, signal);
  const receipt: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(raw));
  if (!object(receipt) || receipt.schema_version !== 1 || receipt.plan_path !== args.plan_path || receipt.plan_sha256 !== sha256(bytes) || JSON.stringify(receipt.selected_action_ids) !== JSON.stringify(selection.selected) || JSON.stringify(receipt.satisfied_action_ids) !== JSON.stringify(selection.satisfied) || !Array.isArray(receipt.states) || receipt.states.length > 10000 || snapshot.files.find(file => file.path === PLAN_STATE_PATH)?.sha256 !== sha256(raw)) throw new Error('PLAN_STATE_RECEIPT_INVALID');
  const states: FileCondition[] = [], seen = new Set<string>();
  for (const value of receipt.states) {
    if (!object(value) || Object.keys(value).sort().join(',') !== 'path,sha256') throw new Error('PLAN_STATE_RECEIPT_INVALID');
    const item = name(value.path), key = portablePathKey(item);
    if (seen.has(key) || value.sha256 !== null && (typeof value.sha256 !== 'string' || !HASH.test(value.sha256)) || (snapshot.files.find(file => file.path === item)?.sha256 ?? null) !== value.sha256) throw new Error('PLAN_STATE_RECEIPT_INVALID');
    seen.add(key); states.push({ path: item, sha256: value.sha256 as string | null });
  }
  if (JSON.stringify(receipt.completed_batches ?? []) !== JSON.stringify(batches)) throw new Error('PLAN_COMPLETION_INVALID');
  for (const expected of dependencyConditions(selection, batches)) if (!states.some(item => item.path === expected.path && item.sha256 === expected.sha256)) throw new Error('PLAN_DEPENDENCY_NOT_SATISFIED');
  const initial = new Map(snapshot.files.map(item => [item.path, item.sha256 as string | null]));
  const final = new Map(initial);
  for (const candidate of candidates) final.set(candidate.path, candidate.after_base64 === null ? null : sha256(Buffer.from(candidate.after_base64, 'base64')));
  for (const id of selection.ordered) {
    const action = selection.actions.get(id)!;
    if (action.input_fingerprints !== undefined) {
      if (!object(action.input_fingerprints)) throw new Error('PLAN_SELECTED_PRECONDITION_MISMATCH');
      for (const [key, value] of Object.entries(action.input_fingerprints)) if (initial.get(name(key)) !== hash(value)) throw new Error('PLAN_SELECTED_PRECONDITION_MISMATCH');
    }
    if (action.type === 'replace_text') {
      const source = name(action.file_path);
      if (initial.get(source) !== hash(action.before_sha256) || typeof action.old_text !== 'string' || !action.old_text || typeof action.new_text !== 'string' || [action.old_text, action.new_text].some(text => Buffer.from(text).toString('utf8') !== text)) throw new Error('PLAN_SELECTED_PRECONDITION_MISMATCH');
      const original = await guardedRead(guard, snapshot.directory, source, 64 * 1024 * 1024, snapshot.snapshot_identity, signal);
      const expected = sha256(new TextDecoder('utf8', { fatal: true }).decode(original).split(action.old_text).join(action.new_text));
      if (final.get(source) !== expected) throw new Error('PLAN_SELECTED_EFFECT_MISMATCH');
      continue;
    }
    if (!['create_file', 'replace_file', 'delete_file', 'rename_file'].includes(action.type as string)) continue;
    // Preserve the legacy optional null spellings for selected actions.
    const normalized = { ...action, ...(action.type === 'create_file' ? { before_sha256: action.before_sha256 ?? null } : {}), ...(action.type === 'delete_file' ? { after_sha256: action.after_sha256 ?? null } : {}), ...(action.type === 'rename_file' ? { target_before_sha256: action.target_before_sha256 ?? null } : {}) };
    const source = name(action.file_path ?? action.source);
    if ((initial.get(source) ?? null) !== (action.type === 'create_file' ? null : action.before_sha256)) throw new Error('PLAN_SELECTED_PRECONDITION_MISMATCH');
    if (action.type === 'rename_file' && initial.has(name(action.target_file_path ?? action.destination))) throw new Error('PLAN_SELECTED_PRECONDITION_MISMATCH');
    for (const expected of actionPostconditions(normalized)) if ((final.get(expected.path) ?? null) !== expected.sha256) throw new Error('PLAN_SELECTED_EFFECT_MISMATCH');
  }
  if (!args.plan_path.startsWith('.ud-agent-inputs/') && !seen.has(portablePathKey(args.plan_path))) states.push({ path: args.plan_path, sha256: sha256(bytes) });
  return { conditions: states, selection, batches, planSha256: sha256(bytes) };
}
