import { readFile } from 'node:fs/promises';
import { captureOperationSnapshot } from '../../workspace/src/input-broker.js';
import type { ContextBundle } from '../../workspace/src/input-broker.js';
import { guardedRead } from '../../workspace/src/guard.js';
import { sha256 } from '../../workspace/src/journal.js';
import { ResourceStore } from './resources.js';
import { planSelection } from '../../workspace/src/plan-state.js';

const RULES = { 'data.json': 'auxiliaries', 'deprels.json': 'deprels', 'edeprels.json': 'edeprels', 'feats.json': 'features', 'tospace.json': 'expressions', 'udeprels.json': 'udeprels', 'upos.json': 'upos' };
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('CONTEXT_DATA_INVALID'); return value as Record<string, unknown>; }
function identity(hashes: Record<string, unknown>): string {
  if (Object.keys(hashes).sort().join(',') !== Object.keys(RULES).join(',') || Object.values(hashes).some(value => typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))) throw new Error('CONTEXT_HASHES_INVALID');
  return sha256(JSON.stringify(Object.fromEntries(Object.keys(RULES).map(name => [name, hashes[name]]))));
}

export async function resolveContextResource(args: Record<string, unknown>, resources: ResourceStore): Promise<ContextBundle | undefined> {
  const value = args.ud_context_path ?? (args.options && typeof args.options === 'object' ? (args.options as Record<string, unknown>).ud_context_path : undefined);
  if (typeof value !== 'string' || !value.startsWith('ud://')) return undefined;
  const bundle = object(JSON.parse((await resources.bytes(value, 'contexts')).toString('utf8')));
  if (typeof bundle.manifest !== 'string' || !bundle.files || typeof bundle.files !== 'object' || Array.isArray(bundle.files) || Object.values(bundle.files).some(value => typeof value !== 'string')) throw new Error('CONTEXT_RESOURCE_INVALID');
  return { uri: value, manifest: bundle.manifest, files: bundle.files as Record<string, string> };
}

/** Prepare selected rule actions as immutable resources, never rewrite upstream rules. */
export async function prepareWorkerContexts(input: { operation: string; args: Record<string, unknown>; result: Record<string, unknown>; guard: string; grants: readonly string[]; contextSha256: string; resources: ResourceStore; installedContext?: string; contextBundle?: ContextBundle }): Promise<Record<string, unknown>> {
  if (input.result.prepared_contexts !== undefined) throw new Error('CONTEXT_ACTION_NOT_AUTHORIZED');
  const changes = input.result.context_changes;
  if (changes === undefined || (Array.isArray(changes) && changes.length === 0)) return input.result;
  if (input.operation !== 'plan_apply' || input.result.status !== 'candidate' || !Array.isArray(changes) || changes.length > 100 || !Array.isArray(input.args.selected_action_ids) || typeof input.args.plan_path !== 'string') throw new Error('CONTEXT_ACTION_NOT_AUTHORIZED');
  const captured = await captureOperationSnapshot(input.guard, input.args, input.grants, undefined, input.installedContext, input.operation, input.contextBundle);
  try {
    const plan = object(JSON.parse((await guardedRead(input.guard, captured.snapshot.directory, captured.arguments.plan_path as string, 64 * 1024 * 1024, captured.snapshot.snapshot_identity)).toString('utf8')));
    if (!Array.isArray(plan.actions)) throw new Error('CONTEXT_ACTION_NOT_AUTHORIZED');
    const selection = planSelection(plan, input.args.selected_action_ids);
    const actions = selection.ordered.map(id => selection.actions.get(id)!).filter(action => action.type === 'prepare_context');
    if (actions.length !== changes.length) throw new Error('CONTEXT_ACTION_NOT_AUTHORIZED');
    let original = input.contextSha256.replace(/^sha256:/, '');
    if (captured.contextPath) {
      const manifest = object(JSON.parse((await guardedRead(input.guard, captured.snapshot.directory, captured.contextPath, 1024 * 1024, captured.snapshot.snapshot_identity)).toString('utf8')));
      original = identity(object(manifest.rules));
    } else if (input.installedContext) original = identity(object(object(JSON.parse(await readFile(input.installedContext, 'utf8'))).rules));
    const prepared = [];
    for (let index = 0; index < changes.length; index++) {
      const change = object(changes[index]), action = actions[index]!;
      for (const key of ['language_code', 'files', 'file_hashes', 'base_hashes', 'context_sha256']) if (JSON.stringify(change[key]) !== JSON.stringify(action[key])) throw new Error('CONTEXT_ACTION_CONTENT_MISMATCH');
      if (identity(object(change.base_hashes)) !== original) throw new Error('CONTEXT_ACTION_STALE');
      const hashes = object(change.file_hashes), files = object(change.files);
      const contextSha = identity(hashes);
      if (contextSha !== change.context_sha256 || Object.keys(files).sort().join(',') !== Object.keys(RULES).join(',')) throw new Error('CONTEXT_ACTION_CONTENT_MISMATCH');
      for (const [name, family] of Object.entries(RULES)) {
        const content = files[name];
        if (typeof content !== 'string' || Buffer.byteLength(content) > 64 * 1024 * 1024 || sha256(content) !== hashes[name]) throw new Error('CONTEXT_ACTION_CONTENT_MISMATCH');
        const parsed = object(JSON.parse(content));
        if (!parsed[family] || typeof parsed[family] !== 'object') throw new Error('CONTEXT_RULE_FAMILY_INVALID');
      }
      const manifest = JSON.stringify({ schema_version: 1, rule_dir: 'rules', rules: hashes, context_sha256: contextSha });
      const resource = await input.resources.put('contexts', Buffer.from(JSON.stringify({ manifest, files })), 'application/json');
      prepared.push({ ...resource, action_id: action.id, context_sha256: contextSha, language_code: change.language_code });
    }
    const count = (Array.isArray(input.result.changes) ? input.result.changes.length : 0) + (Array.isArray(input.result.file_operations) ? input.result.file_operations.length : 0);
    return { ...input.result, context_changes: [], prepared_contexts: prepared, requires_host_commit: count > 0 };
  } finally { await captured.snapshot.cleanup(); }
}

/** Re-read the immutable publication and bind it to the exact selected rule action. */
export async function verifyPublishedPlanContext(action: Record<string, unknown>, reference: { uri: string; sha256: string; context_sha256: string }, resources: ResourceStore): Promise<void> {
  const bytes = await resources.bytes(reference.uri, 'contexts');
  if (sha256(bytes) !== reference.sha256 || action.type !== 'prepare_context' || reference.context_sha256 !== action.context_sha256) throw new Error('PLAN_COMPLETION_CONTEXT_CHANGED');
  const value = object(JSON.parse(bytes.toString('utf8'))), manifest = object(JSON.parse(String(value.manifest)));
  if (manifest.rule_dir !== 'rules' || identity(object(manifest.rules)) !== reference.context_sha256 || identity(object(action.file_hashes)) !== reference.context_sha256) throw new Error('PLAN_COMPLETION_CONTEXT_CHANGED');
  const files = object(value.files), expected = object(action.files), hashes = object(action.file_hashes);
  if (Object.keys(files).sort().join(',') !== Object.keys(RULES).join(',')) throw new Error('PLAN_COMPLETION_CONTEXT_CHANGED');
  for (const name of Object.keys(RULES)) if (typeof files[name] !== 'string' || files[name] !== expected[name] || sha256(files[name] as string) !== hashes[name]) throw new Error('PLAN_COMPLETION_CONTEXT_CHANGED');
}
