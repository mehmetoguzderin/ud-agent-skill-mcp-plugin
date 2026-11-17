import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { sha256 } from '../../packages/workspace/src/journal.js';
import { captureOperationSnapshot } from '../../packages/workspace/src/input-broker.js';
import { prepareWorkerContexts, resolveContextResource } from '../../packages/coordinator/src/context-broker.js';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';

it('prepares only selected rule actions as immutable scoped contexts and reuses exact bytes in a worker snapshot', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-context-broker-')));
  const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
  try {
    const workspace = path.join(root, 'workspace'); await mkdir(workspace);
    const resources = await ResourceStore.open(path.join(root, 'resources'), [workspace], guard);
    const families = { 'data.json': 'auxiliaries', 'deprels.json': 'deprels', 'edeprels.json': 'edeprels', 'feats.json': 'features', 'tospace.json': 'expressions', 'udeprels.json': 'udeprels', 'upos.json': 'upos' };
    const files = Object.fromEntries(Object.entries(families).map(([name, family]) => [name, JSON.stringify({ [family]: { en: ['changed'] } })]));
    const file_hashes = Object.fromEntries(Object.entries(files).map(([name, bytes]) => [name, sha256(bytes)]));
    const base_hashes = Object.fromEntries(Object.keys(files).map(name => [name, 'a'.repeat(64)]));
    const action = { id: 'rules', type: 'prepare_context', language_code: 'en', files, file_hashes, base_hashes, context_sha256: sha256(JSON.stringify(file_hashes)), depends_on: [] };
    await writeFile(path.join(workspace, 'plan.json'), JSON.stringify({ schema_version: 'ud-plan-v1', actions: [action] }));
    const args = { working_tree_path: workspace, plan_path: 'plan.json', selected_action_ids: ['rules'], options: { mode: 'apply' }, ud_context_path: '' };
    const { id: _id, type: _type, ...change } = action;
    const result = { status: 'candidate', changes: [], file_operations: [], requires_host_commit: true, context_changes: [change] };
    const input = { operation: 'plan_apply', args, result, guard, grants: [workspace], contextSha256: `sha256:${sha256(JSON.stringify(base_hashes))}`, resources };
    const prepared = await prepareWorkerContexts(input);
    expect(prepared).toMatchObject({ context_changes: [], requires_host_commit: false, prepared_contexts: [{ context_sha256: action.context_sha256 }] });
    const reference = (prepared.prepared_contexts as { uri: string }[])[0]!;
    expect(reference.uri).toMatch(/^ud:\/\/contexts\/[a-f0-9]{64}$/);
    expect((await prepareWorkerContexts(input)).prepared_contexts).toEqual(prepared.prepared_contexts);
    const next = { working_tree_path: workspace, file_paths: ['input.conllu'], ud_context_path: reference.uri };
    await writeFile(path.join(workspace, 'input.conllu'), '# sent_id = 1\n');
    const bundle = await resolveContextResource(next, resources);
    const captured = await captureOperationSnapshot(guard, next, [workspace], undefined, undefined, 'validation_report', bundle);
    try {
      expect(captured.arguments.ud_context_path).toMatch(/^\.ud-agent-inputs\/context-[a-f0-9]{64}\/context.json$/);
      expect(captured.snapshot.files.filter(file => file.path.includes('/rules/'))).toHaveLength(7);
      expect(captured.snapshot.files.find(file => file.path.endsWith('/rules/upos.json'))?.sha256).toBe(file_hashes['upos.json']);
    } finally { await captured.snapshot.cleanup(); }
    await expect(prepareWorkerContexts({ ...input, contextSha256: `sha256:${'0'.repeat(64)}` })).rejects.toThrow('CONTEXT_ACTION_STALE');
    await expect(prepareWorkerContexts({ ...input, args: { ...args, selected_action_ids: [] } })).rejects.toThrow('CONTEXT_ACTION_NOT_AUTHORIZED');
    const other = await ResourceStore.open(path.join(root, 'resources'), ['/other'], guard);
    await expect(resolveContextResource(next, other)).rejects.toThrow('RESOURCE_ACCESS_DENIED');
  } finally { await rm(root, { recursive: true, force: true }); }
}, 30_000);
