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
test('actual operation handoff exposes returned findings and counts while retaining structured results', async () => dispatch('treebank_profile', { status: 'complete', passed: false, sentence_count: 7, metrics: { matched: 5 }, incidents: [{ message: 'Fixture finding' }] }, response => {
  const text = response.content.find(item => item.type === 'text');expect(text?.type).toBe('text');
  const summary = JSON.parse((text as { text: string }).text);
  expect(summary).toMatchObject({ kind: 'ud-result-summary', execution: 'completed', facts: { '/result/passed': false, '/result/sentence_count': 7, '/result/metrics/matched': 5 } });
  expect(response.structuredContent.result).toMatchObject({ status: 'complete', passed: false, sentence_count: 7, metrics: { matched: 5 }, incidents: [{ message: 'Fixture finding' }] });
  expect(Buffer.byteLength((text as { text: string }).text)).toBeLessThanOrEqual(4096);
}));
