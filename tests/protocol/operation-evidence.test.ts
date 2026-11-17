/** Public coordinator dispatch with an explicit fixture worker; no engine readiness is fabricated. */
import { beforeEach, expect, test, vi } from 'vitest';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
const fixture = vi.hoisted(() => ({ result: {} as Record<string, unknown>, run: vi.fn() }));
vi.mock('../../packages/runtime-manager/src/environment.js', async importOriginal => ({ ...await importOriginal<typeof import('../../packages/runtime-manager/src/environment.js')>(), checkEnvironment: async () => ({ ready: true, runtime: { engine: 'docker', executable: '/fixture/docker' } }) }));
vi.mock('../../packages/coordinator/src/provider-runtime.js', () => ({ providerInspection: vi.fn(), providerReadiness: vi.fn(), setupProvider: vi.fn(), resolveAdmittedProvider: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), image: { digest: 'sha256:' + 'a'.repeat(64), contextSha256: 'sha256:' + 'b'.repeat(64) }, stateRoot: '/unused-fixture-state', run: fixture.run }) }));
vi.mock('../../packages/runtime-manager/src/receipt.js', async importOriginal => ({ ...await importOriginal<typeof import('../../packages/runtime-manager/src/receipt.js')>(), loadNativeGuardReceipt: async () => ({ guard: path.resolve('target/debug/ud-agent-guard.exe') }) }));
import { executeOperation } from '../../packages/coordinator/src/operations.js';
import { loadContracts } from '../../packages/coordinator/src/catalog.js';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';
const { domain } = loadContracts(process.cwd());
async function dispatch(name: string, result: Record<string, unknown>, action: (response: Awaited<ReturnType<typeof executeOperation>>, resources: ResourceStore) => Promise<void> | void, observe?: NonNullable<Parameters<typeof executeOperation>[5]>['observe']) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-operation-evidence-'))), workspace = path.join(root, 'bank'); await mkdir(workspace);await writeFile(path.join(workspace, 'a.conllu'), 'snapshot fixture');
  try {
    fixture.result = result;fixture.run.mockResolvedValue({ result, snapshot: { sha256: 'c'.repeat(64), files: [{ path: 'a.conllu', sha256: 'd'.repeat(64), size: 16 }, { path: '.ud-agent-inputs/peer/a.conllu', sha256: 'e'.repeat(64), size: 9 }] } });
    const resources = await ResourceStore.open(path.join(root, 'resources'), [workspace], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
    const contract = domain.find(row => row.name === name);if (!contract) throw new Error('Missing real operation contract');
    const response = await executeOperation(contract, { working_tree_path: workspace, ud_context_path: '' }, domain, { sourceRoot: process.cwd(), userspaceStateRoot: path.join(root, 'state'), allowedRoots: [workspace] }, undefined, { resources, ...(observe ? { observe } : {}) });
    expect(response.isError, JSON.stringify(response)).toBeUndefined();await action(response, resources);
  } finally { await rm(root, { recursive: true, force: true }); }
}
beforeEach(() => fixture.run.mockReset());
test('public OCI analysis preserves array scopes and reports operation execution without invented validation', async () => dispatch('treebank_profile', { sentence_count: 1, scope: ['a.conllu'] }, response => {
  expect(response.structuredContent.scope).toEqual({ file_paths: ['a.conllu'] });
  expect(response.structuredContent.coverage).toEqual({ requested: ['domain_operation'], completed: ['domain_operation'], skipped: [] });
  expect(response.structuredContent.coverage.completed).not.toContain('validation');
}));
test('public read reports derive actual closed input scope and retain independently reported check families', async () => dispatch('lexeme_pos_report', { entries: [], coverage: { content: 'completed', documentation: 'not_requested', repository: 'incomplete' } }, response => {
  expect(response.structuredContent.scope).toMatchObject({ file_paths: ['a.conllu'] });
  expect(response.structuredContent.scope.file_paths).not.toContain('.ud-agent-inputs/peer/a.conllu');
  expect(response.structuredContent.coverage).toEqual({ requested: ['content', 'repository'], completed: ['content'], skipped: [{ name: 'repository', reason: 'incomplete' }] });
}));
test('domain metric counts, descriptions and graph drawing coverage remain distinct from linguistic check families', async () => {
  for (const coverage of [{ requested: 10, complete: 8 }, { source_characters: 10, target_characters: 12 }, { scope: 'CoNLL-U files', base_identity_verified: true }, { basic_dependencies: 'drawn' }]) await dispatch('treebank_profile', { sentence_count: 1, coverage }, response => {
    expect(response.structuredContent.result.coverage).toEqual(coverage);
    expect(response.structuredContent.coverage).toEqual({ requested: ['domain_operation'], completed: ['domain_operation'], skipped: [] });
  });
}, 30_000);
test('public versioned complete plans are immutable plan resources rather than report resources', async () => dispatch('metadata_change_plan', { schema_version: 'ud-plan-v1', status: 'complete', actions: [] }, async (response, resources) => {
  const reference = response.structuredContent.result.report_resource as { uri: string };expect(reference.uri).toMatch(/^ud:\/\/plans\//);
  const stored = JSON.parse((await resources.bytes(reference.uri, 'plans')).toString());expect(stored.operation).toBe('metadata_change_plan');expect(stored.result).toEqual({ schema_version: 'ud-plan-v1', status: 'complete', actions: [] });
  await expect(resources.bytes(reference.uri, 'reports')).rejects.toThrow('RESOURCE_URI_INVALID');
}));
test('public legacy plan workflows use plan resources without changing their successful result fields', async () => dispatch('workspace_sync_plan', { status: 'complete', repositories: [{ path: '.', status: 'matching_snapshots' }] }, response => {
  expect(response.structuredContent.result).toMatchObject({ status: 'complete', repositories: [{ path: '.', status: 'matching_snapshots' }] });
  expect((response.structuredContent.result.report_resource as { uri: string }).uri).toMatch(/^ud:\/\/plans\//);
}));
test('the internal observer records actual dispatch and returned execution evidence without accepting public trace fields', async () => {
  const events: unknown[] = [];
  await dispatch('treebank_profile', { sentence_count: 1 }, response => {
    expect(events).toEqual([{ type: 'tool_call', name: 'treebank_profile' }, { type: 'tool_result', name: 'treebank_profile', execution: response.structuredContent.execution, provenance: response.structuredContent.provenance }]);
  }, event => events.push(event));
  expect(fixture.run).toHaveBeenCalledTimes(1);
});
