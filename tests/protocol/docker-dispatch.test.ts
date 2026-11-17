import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../packages/runtime-manager/src/profiles.js', async original => (await import('../runtime/posix-policy-fixture.js')).physicalExecutablePolicyFixture(await original<typeof import('../../packages/runtime-manager/src/profiles.js')>()));
const mocks = vi.hoisted(() => ({ readiness: vi.fn(), setup: vi.fn(), admitted: vi.fn(), verify: vi.fn(), run: vi.fn(), inspection: vi.fn() }));
vi.mock('../../packages/coordinator/src/docker-readiness.js', () => ({ dockerReadiness: mocks.readiness, setupDocker: mocks.setup, resolveAdmittedDockerAuthority: mocks.admitted, dockerStateRoot: (options: { userspaceStateRoot?: string }) => options.userspaceStateRoot ? `${options.userspaceStateRoot}-docker` : '/fixture/private-state' }));
vi.mock('../../packages/coordinator/src/docker-authority.js', () => ({ verifyDockerAuthority: mocks.verify, resolveProductGuard: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard') }) }));
vi.mock('../../packages/coordinator/src/docker-worker.js', () => ({ runDockerValidation: mocks.run }));
vi.mock('../../packages/runtime-manager/src/docker-inspection.js', () => ({ inspectLocalDocker: mocks.inspection }));
// This fixture supplies an already-built native helper; state operations still execute it.
vi.mock('../../packages/runtime-manager/src/receipt.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/receipt.js')>(), loadNativeGuardReceipt: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard') }) }));
import { loadContracts } from '../../packages/coordinator/src/catalog.js';
import { executeOperation } from '../../packages/coordinator/src/operations.js';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';
import { captureOperationSnapshot } from '../../packages/workspace/src/input-broker.js';
import { sha256 } from '../../packages/workspace/src/journal.js';

const sha = (n: string) => `sha256:${n.repeat(64)}`;
const host = { platform: 'darwin', arch: 'arm64' };
const { domain, environment } = loadContracts(path.resolve('.'));
const contract = (name: string) => { const found = [...domain, ...environment].find(item => item.name === name); if (!found) throw new Error(`Missing ${name}`); return found; };

async function fixture(test: (bin: string, workspace: string, sourceRoot: string) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-docker-dispatch-')));
  try {
    const bin = path.join(root, 'bin'); const workspace = path.join(root, 'workspace'); const release = path.join(root, 'release');
    await mkdir(bin); await mkdir(workspace); await mkdir(path.join(release, 'runtime'), { recursive: true });
    const engine = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')); await writeFile(engine, '#!/bin/sh\nexit 0\n', { mode: 0o700 }); await chmod(engine, 0o700);
    await writeFile(path.join(release, 'runtime', 'runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'unbuilt', packs: {} }));
    await test(bin, workspace, release);
  } finally { await rm(root, { recursive: true, force: true }); }
}

describe('Docker public validation routing with a simulated adapter', () => {
  it('applies a public constrained plan with host-only validation options and the exact staged custom context', async () => fixture(async (bin, workspace, sourceRoot) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')), guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
    const authority = { engine: executable, engineSha256: sha('1'), guard, guardSha256: sha('2'), image: { digest: sha('3'), contextSha256: sha('4'), reference: `ghcr.io/mehmetoguzderin/core@${sha('3')}` }, identity: { endpoint: 'unix:///fixture.sock', daemonId: 'fixture', imageId: sha('5'), rootless: false } };
    const ready = { engine: 'docker', executable, rootless: false, image_digest: sha('3'), context_sha256: sha('4'), verification: 'verified', available_operations: ['plan_apply', 'validation_report'] };
    mocks.readiness.mockResolvedValue(ready); mocks.admitted.mockResolvedValue({ authority, readiness: ready }); mocks.verify.mockResolvedValue(authority);
    const before = '# sent_id = one\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n', after = before.replace('\thi\t', '\thello\t');
    await writeFile(path.join(workspace, 'a.conllu'), before);
    await mkdir(path.join(workspace, 'rules'));
    const names = ['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'];
    for (const name of names) await writeFile(path.join(workspace, 'rules', name), '{}');
    await writeFile(path.join(workspace, 'rules/context.json'), JSON.stringify({ rule_dir: '.', rules: Object.fromEntries(names.map(name => [name, sha256('{}')])) }));
    await writeFile(path.join(workspace, 'plan.json'), JSON.stringify({ schema_version: 'ud-plan-v1', actions: [{ id: 'lemma', type: 'replace_file', file_path: 'a.conllu', before_sha256: sha256(before), after_sha256: sha256(after), content: after, depends_on: [] }] }));
    const args = { working_tree_path: workspace, plan_path: 'plan.json', selected_action_ids: ['lemma'], options: { mode: 'apply', idempotency_key: 'public-plan', validation_options: { language_code: 'en', level: 2 }, ud_context_path: 'rules/context.json' } };
    const captured = await captureOperationSnapshot(guard, args, [workspace], undefined, undefined, 'plan_apply');
    const snapshot = { sha256: captured.snapshot.sha256, files: captured.snapshot.files, root_identity: captured.snapshot.root_identity, source_map: captured.sourceMap }; await captured.snapshot.cleanup();
    mocks.run.mockImplementation(async (input: { operation: string; arguments: Record<string, unknown> }) => {
      if (input.operation === 'plan_apply') {
        expect(input.arguments.options).toEqual({ mode: 'apply' });
        expect(input.arguments.ud_context_path).toBe('rules/context.json');
        return { result: { status: 'candidate', changes: [{ file_path: 'a.conllu', before_sha256: sha256(before), after_sha256: sha256(after), content: after }], requires_host_commit: true }, snapshot };
      }
      expect(input.operation).toBe('validation_report');
      expect(input.arguments.options).toEqual({ language_code: 'en', level: 2 });
      const context = input.arguments.ud_context_path as string;
      expect(context).not.toBe(path.join(workspace, 'rules/context.json'));
      expect(JSON.parse(await readFile(context, 'utf8'))).toMatchObject({ rule_dir: '.' });
      expect(await readFile(path.join(path.dirname(context), 'upos.json'), 'utf8')).toBe('{}');
      return { result: { passed: true, incidents: [], coverage: { content: 'completed' } }, snapshot };
    });
    const options = { sourceRoot, host, searchPath: bin, allowedRoots: [workspace], userspaceStateRoot: path.join(workspace, 'private') };
    const applied = await executeOperation(contract('plan_apply'), args, domain, options);
    expect(applied.isError).toBeUndefined(); expect(applied.structuredContent.result).toMatchObject({ transaction: { status: 'completed' }, validation: { passed: true } });
    expect(await readFile(path.join(workspace, 'a.conllu'), 'utf8')).toBe(after);
    const replayed = await executeOperation(contract('plan_apply'), args, domain, options);
    expect(replayed.isError).toBeUndefined(); expect(replayed.structuredContent.result).toMatchObject({ replayed: true, transaction: { status: 'completed' } });
    expect(mocks.run).toHaveBeenCalledTimes(2);
  }), 30000);
  it('keeps a complete large incident report in authorized immutable resources rather than overflowing MCP stdio', async () => fixture(async (bin, workspace, sourceRoot) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : ''));
    const authority = { engine: executable, engineSha256: sha('1'), guard: '/fixture/guard', guardSha256: sha('2'), image: { digest: sha('3'), contextSha256: sha('4'), reference: `ghcr.io/mehmetoguzderin/core@${sha('3')}` }, identity: { endpoint: 'unix:///fixture.sock', daemonId: 'fixture', imageId: sha('5'), rootless: false } };
    const ready = { engine: 'docker', executable, rootless: false, image_digest: sha('3'), context_sha256: sha('4'), verification: 'verified', available_operations: ['validation_report'] };
    mocks.readiness.mockResolvedValue(ready); mocks.admitted.mockResolvedValue({ authority, readiness: ready }); mocks.verify.mockResolvedValue(authority);
    const incidents = Array.from({ length: 6000 }, (_, index) => ({ testid: 'expected-incident', lineno: index + 1, message: 'An independently counted large report.' }));
    mocks.run.mockResolvedValue({ result: { passed: false, incidents, coverage: { content: 'completed' } }, snapshot: { sha256: sha('6'), files: [{ path: 'a.conllu', size: 5, sha256: sha('7') }] } });
    const resources = await ResourceStore.open(path.join(workspace, 'resources'), [workspace], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
    const result = await executeOperation(contract('validation_report'), { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '', options: { language_code: 'en' } }, domain, { sourceRoot, host, searchPath: bin, allowedRoots: [workspace], userspaceStateRoot: path.join(workspace, 'private') }, undefined, { resources });
    expect(result.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { status: 'resource', passed: false, summary: { incident_count: 6000 } } });
    expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThan(8192);
    const reference = result.structuredContent.result.report_resource as { uri: string };
    const stored = JSON.parse((await resources.bytes(reference.uri, 'reports')).toString('utf8'));
    expect(stored.result.incidents).toEqual(incidents);
    expect(stored.diagnostics).toEqual(incidents);
  }));
  it('prepares the verified OCI route on the first harness request and persists the selected runtime', async () => fixture(async (bin, workspace, sourceRoot) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : ''));
    const authority = { engine: executable, engineSha256: sha('1'), guard: '/fixture/guard', guardSha256: sha('2'), image: { digest: sha('3'), contextSha256: sha('4'), reference: `ghcr.io/mehmetoguzderin/core@${sha('3')}` }, identity: { endpoint: 'unix:///fixture.sock', daemonId: 'fixture', imageId: sha('5'), rootless: false } };
    const ready = { engine: 'docker', executable, rootless: false, image_digest: sha('3'), context_sha256: sha('4'), verification: 'verified', available_operations: ['validation_report'] };
    mocks.readiness.mockResolvedValue(null);
    mocks.setup.mockImplementation(async () => { mocks.readiness.mockResolvedValue(ready); return ready; });
    mocks.admitted.mockResolvedValue({ authority, readiness: ready }); mocks.verify.mockResolvedValue(authority);
    mocks.run.mockResolvedValue({ result: { passed: true, incidents: [], coverage: { content: 'completed' } }, snapshot: { sha256: sha('6'), files: [{ path: 'a.conllu', size: 5, sha256: sha('7') }] } });
    const options = { sourceRoot, host, searchPath: bin, allowedRoots: [workspace], userspaceStateRoot: path.join(workspace, 'private'), autoSetup: true };
    const args = { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '', options: { language_code: 'en' } };
    const result = await executeOperation(contract('validation_report'), args, domain, options);
    expect(result.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { passed: true } });
    expect(mocks.setup).toHaveBeenCalledOnce(); expect(mocks.run).toHaveBeenCalledOnce();
    await executeOperation(contract('validation_report'), args, domain, options);
    expect(mocks.setup).toHaveBeenCalledOnce(); expect(mocks.run).toHaveBeenCalledTimes(2);
  }));
  beforeEach(() => {
    for (const fn of Object.values(mocks)) fn.mockReset();
    mocks.inspection.mockResolvedValue({ status: 'available', rootless: false, reason: 'fixture' });
  });

  it('uses coordinator-owned setup evidence and dispatches the verified identity and grant', async () => fixture(async (bin, workspace, sourceRoot) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : ''));
    const authority = { engine: executable, engineSha256: sha('1'), guard: '/fixture/guard', guardSha256: sha('2'), image: { digest: sha('3'), contextSha256: sha('4'), reference: `ghcr.io/mehmetoguzderin/core@${sha('3')}` }, identity: { endpoint: 'unix:///fixture.sock', daemonId: 'fixture', imageId: sha('5'), rootless: false } };
    const ready = { engine: 'docker', executable, rootless: false, image_digest: authority.image.digest, context_sha256: authority.image.contextSha256, verification: 'verified', available_operations: ['validation_report'] };
    let setup = false;
    mocks.setup.mockImplementation(async () => { setup = true; return ready; });
    mocks.readiness.mockImplementation(async () => setup ? ready : null);
    mocks.admitted.mockImplementation(async () => setup ? { authority, readiness: ready } : null);
    mocks.verify.mockResolvedValue(authority);
    mocks.run.mockResolvedValue({ result: { passed: false, scope: { file_paths: ['a.conllu'] }, incidents: [{ testid: 'non-unique-sent-id' }], coverage: { content: 'completed' } }, snapshot: { sha256: sha('6'), files: [{ path: 'a.conllu', size: 5, sha256: sha('7') }] } });
    const forged = vi.fn().mockResolvedValue(ready);
    const options = { sourceRoot, host, searchPath: bin, allowedRoots: [workspace], userspaceStateRoot: path.join(workspace, 'private'), ociReadiness: forged, ociSetup: forged, ociAdmission: forged };
    const prep = await executeOperation(contract('setup_ud_environment'), { engine: 'docker', working_tree_path: workspace, required_tools: ['validation_report'] }, domain, options);
    expect(prep.structuredContent.result).toMatchObject({ status: 'ready', ready: true, runtime: { engine: 'docker' } });
    expect(mocks.setup).toHaveBeenCalledOnce(); expect(forged).not.toHaveBeenCalled();
    const args = { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '', options: { language_code: 'en' } };
    const abort = new AbortController();
    const result = await executeOperation(contract('validation_report'), args, domain, options, abort.signal);
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { passed: false }, provenance: { runtime: 'docker', image_digest: authority.image.digest }, inputs: { snapshot_sha256: sha('6') }, diagnostics: [{ testid: 'non-unique-sent-id' }] });
    expect(mocks.run).toHaveBeenCalledWith(expect.objectContaining({ expectedIdentity: authority.identity, allowedRoots: [workspace], filePaths: ['a.conllu'], signal: abort.signal }));
    expect(mocks.verify).toHaveBeenCalledWith(authority);
  }));

  it('rejects stale admission and custom contexts before starting a worker', async () => fixture(async (bin, workspace, sourceRoot) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : ''));
    const ready = { engine: 'docker', executable, rootless: false, image_digest: sha('1'), context_sha256: sha('2'), verification: 'verified', available_operations: ['validation_report'] };
    mocks.readiness.mockResolvedValue(ready); mocks.admitted.mockResolvedValue(null);
    const options = { sourceRoot, host, searchPath: bin, allowedRoots: [workspace], userspaceStateRoot: path.join(workspace, 'private') };
    const base = { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' };
    const stale = await executeOperation(contract('validation_report'), base, domain, options);
    expect(stale.isError).toBe(true); expect(stale.structuredContent.result.reason).toBe('DOCKER_READINESS_CHANGED');
    const custom = await executeOperation(contract('validation_report'), { ...base, ud_context_path: '/unverified/rules' }, domain, options);
    expect(custom.isError).toBe(true); expect(custom.structuredContent.result.reason).toContain('DOCKER_CONTEXT_UNAVAILABLE');
    expect(mocks.run).not.toHaveBeenCalled();
  }));

  it('dispatches built-in analysis and runs project checks in a distinct fresh worker', async () => fixture(async (bin, workspace, sourceRoot) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : ''));
    const authority = { engine: executable, engineSha256: sha('1'), guard: '/fixture/guard', guardSha256: sha('2'), image: { digest: sha('3'), contextSha256: sha('4'), reference: `ghcr.io/mehmetoguzderin/core@${sha('3')}` }, identity: { endpoint: 'unix:///fixture.sock', daemonId: 'fixture', imageId: sha('5'), rootless: false } };
    const ready = { engine: 'docker', executable, rootless: false, image_digest: sha('3'), context_sha256: sha('4'), verification: 'verified', available_operations: ['validation_report', 'treebank_profile', 'project_consistency_report'] };
    mocks.readiness.mockResolvedValue(ready); mocks.admitted.mockResolvedValue({ authority, readiness: ready }); mocks.verify.mockResolvedValue(authority);
    const snapshot = { sha256: sha('6'), files: [{ path: 'a.conllu', size: 5, sha256: sha('7') }, { path: 'rules.py', size: 17, sha256: sha('8') }] };
    mocks.run.mockImplementation(async ({ operation }: { operation: string }) => ({ result: operation === 'treebank_profile' ? { sentence_count: 3 } : { passed: operation !== '_project_rules', incidents: [{ testid: operation }], coverage: { content: 'completed' } }, snapshot }));
    const options = { sourceRoot, host, searchPath: bin, allowedRoots: [workspace], userspaceStateRoot: path.join(workspace, 'private') };
    const analysis = await executeOperation(contract('treebank_profile'), { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, domain, options);
    expect(analysis.structuredContent.result).toMatchObject({ sentence_count: 3 });
    expect(mocks.run).toHaveBeenCalledWith(expect.objectContaining({ operation: 'treebank_profile' }));
    mocks.run.mockClear();
    const result = await executeOperation(contract('project_consistency_report'), { working_tree_path: workspace, ud_context_path: '', validator_module_path: 'rules.py', validator_class_name: 'Rules', options: { language_code: 'en' } }, domain, options);
    expect(mocks.run.mock.calls.map(([input]) => input.operation)).toEqual(['validation_report', '_project_rules']);
    expect(result.structuredContent.result).toMatchObject({ status: 'complete', passed: false, official: { passed: true }, project: { passed: false }, coverage: { content: 'completed', official_validation: 'completed', project_rules: 'completed' }, provenance: { validator_module_path: 'rules.py', validator_class_name: 'Rules', source_sha256: sha('8'), project_code: { file_path: 'rules.py', sha256: sha('8'), size_bytes: 17, validator_class_name: 'Rules' } } });
    mocks.run.mockImplementation(async ({ operation }: { operation: string }) => { if (operation === '_project_rules') throw new Error('PROJECT_VALIDATOR_FAILED'); return { result: { passed: false, incidents: [{ testid: 'official' }] }, snapshot }; });
    const failed = await executeOperation(contract('project_consistency_report'), { working_tree_path: workspace, ud_context_path: '', validator_module_path: 'rules.py', validator_class_name: 'Rules' }, domain, options);
    expect(failed.isError).toBe(true);
    expect(failed.structuredContent.result).toMatchObject({ status: 'incomplete', official: { passed: false, incidents: [{ testid: 'official' }] }, coverage: { official_validation: 'completed', project_rules: 'incomplete' } });
  }));
});
