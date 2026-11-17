/** Internal request scope for host-admitted, durable completed plan batches. */
import { AsyncLocalStorage } from 'node:async_hooks';
import path from 'node:path';
import { sha256 } from './journal.js';
import { validPortablePath } from './portable-path.js';

export type CompletedPlanBatch = {
  schema_version: 1; workspace: string; identity: { device: string; inode: string };
  plan_path: string; plan_sha256: string; action_ids: string[]; actions_sha256: string; snapshot_sha256: string;
  transaction_id: string | null; request_hash: string | null;
  outputs: { path: string; sha256: string | null }[];
  contexts: { action_id: string; uri: string; sha256: string; context_sha256: string }[];
  validation: 'passed' | 'context-publication';
};
const scope = new AsyncLocalStorage<readonly CompletedPlanBatch[]>();
const HASH = /^[0-9a-f]{64}$/;
export function canonical(value: unknown): string { return JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : item); }
export function actionSetHash(actions: Map<string, Record<string, unknown>>, ids: readonly string[]): string { return sha256(canonical(ids.map(id => actions.get(id)))); }
export function completedPlanBatch(value: unknown): CompletedPlanBatch {
  const bad = (): never => { throw new Error('PLAN_COMPLETION_INVALID'); };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return bad();
  const x = value as CompletedPlanBatch;
  if (Object.keys(x).sort().join(',') !== 'action_ids,actions_sha256,contexts,identity,outputs,plan_path,plan_sha256,request_hash,schema_version,snapshot_sha256,transaction_id,validation,workspace' || x.schema_version !== 1 || typeof x.workspace !== 'string' || !path.isAbsolute(x.workspace) || !x.identity || !/^\d+$/.test(x.identity.device) || !/^\d+$/.test(x.identity.inode) || !validPortablePath(x.plan_path) || ![x.plan_sha256, x.actions_sha256, x.snapshot_sha256].every(item => typeof item === 'string' && HASH.test(item)) || !Array.isArray(x.action_ids) || !x.action_ids.length || x.action_ids.length > 1000 || x.action_ids.some(id => typeof id !== 'string' || !id) || new Set(x.action_ids).size !== x.action_ids.length || !Array.isArray(x.outputs) || x.outputs.length > 1000 || !Array.isArray(x.contexts) || x.contexts.length > 100 || !['passed', 'context-publication'].includes(x.validation)) return bad();
  if ((x.transaction_id === null) !== (x.request_hash === null) || x.transaction_id !== null && (typeof x.transaction_id !== 'string' || !HASH.test(x.transaction_id) || typeof x.request_hash !== 'string' || !HASH.test(x.request_hash)) || x.outputs.length === 0 && x.contexts.length === 0 || x.outputs.length > 0 && (x.transaction_id === null || x.validation !== 'passed') || x.outputs.length === 0 && (x.transaction_id !== null || x.validation !== 'context-publication')) return bad();
  const names = new Set<string>();
  for (const item of x.outputs) {
    if (!item || Object.keys(item).sort().join(',') !== 'path,sha256' || typeof item.path !== 'string' || !validPortablePath(item.path) || names.has(item.path) || item.sha256 !== null && (typeof item.sha256 !== 'string' || !HASH.test(item.sha256))) return bad();
    names.add(item.path);
  }
  const contexts = new Set<string>();
  for (const item of x.contexts) {
    if (!item || Object.keys(item).sort().join(',') !== 'action_id,context_sha256,sha256,uri' || !x.action_ids.includes(item.action_id) || contexts.has(item.action_id) || typeof item.uri !== 'string' || !/^ud:\/\/contexts\/(?:[0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.test(item.uri) || ![item.sha256, item.context_sha256].every(hash => typeof hash === 'string' && HASH.test(hash))) return bad();
    contexts.add(item.action_id);
  }
  if (Buffer.byteLength(JSON.stringify(x)) > 1024 * 1024) return bad();
  return structuredClone(x);
}
export function withCompletedPlanBatches<T>(batches: readonly CompletedPlanBatch[], action: () => T): T { return scope.run(batches, action); }
export function currentCompletedPlanBatches(): readonly CompletedPlanBatch[] { return scope.getStore() ?? []; }
