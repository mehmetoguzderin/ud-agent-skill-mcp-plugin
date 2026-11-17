/** Real MCP progress routing with explicitly simulated runtime/worker calls. */
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, test, vi } from 'vitest';

const calls = vi.hoisted(() => ({ stateRoot: '', check: vi.fn(), setup: vi.fn(), run: vi.fn(), release: vi.fn() }));
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
vi.mock('../../packages/runtime-manager/src/userspace.js', async original => ({
  ...await original<typeof import('../../packages/runtime-manager/src/userspace.js')>(),
  userspaceStateRoot: () => calls.stateRoot, acquireUserspaceLease: async () => calls.release,
}));
vi.mock('../../packages/runtime-manager/src/environment.js', async original => ({
  ...await original<typeof import('../../packages/runtime-manager/src/environment.js')>(),
  checkEnvironment: (...args: unknown[]) => calls.check(...args),
  setupEnvironment: (...args: unknown[]) => calls.setup(...args),
  verifiedUserspaceExecution: () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), manifestSha256: 'a'.repeat(64), contextPath: '/unused-fixture-context' }),
}));
vi.mock('../../packages/runtime-manager/src/receipt.js', async original => ({
  ...await original<typeof import('../../packages/runtime-manager/src/receipt.js')>(),
  loadNativeGuardReceipt: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard') }),
}));
vi.mock('../../packages/coordinator/src/docker-authority.js', async original => ({
  ...await original<typeof import('../../packages/coordinator/src/docker-authority.js')>(),
  resolveProductGuard: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard') }),
}));
vi.mock('../../packages/coordinator/src/provider-runtime.js', () => ({
  providerInspection: vi.fn(), providerReadiness: vi.fn(), setupProvider: vi.fn(),
  resolveAdmittedProvider: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), stateRoot: calls.stateRoot + '-provider', image: { digest: 'sha256:' + 'a'.repeat(64), contextSha256: 'sha256:' + 'b'.repeat(64) }, run: (...args: unknown[]) => calls.run(...args) }),
}));
vi.mock('../../packages/coordinator/src/userspace-worker.js', () => ({ runUserspaceValidation: (...args: unknown[]) => calls.run(...args) }));
import { createServer } from '../../packages/coordinator/src/server.js';
import { executeOperation } from '../../packages/coordinator/src/operations.js';
import { loadContracts } from '../../packages/coordinator/src/catalog.js';
// Every case here starts a real MCP server plus simulated runtime calls (about
// 1.5 s idle). The 5 s default timed out once under full-suite CPU load, so
// the budget is raised for this file only; assertions are unchanged.
vi.setConfig({ testTimeout: 30_000 });

type Progress = { progress: number; total?: number; message?: string };
const environment = (ready = true) => ({ requested_tools: [], platform: { os: process.platform, arch: process.arch }, working_tree_changes: [], status: ready ? 'ready' : 'blocked_by_policy', ready, runtime: { engine: 'docker', executable: '/fixture/docker' } });
const workerResult = () => ({ result: { sentence_count: 1, word_count: 1, multiword_token_count: 0, empty_node_count: 0, upos: [], scope: ['a.conllu'], definition: 'Explicit worker fixture' }, snapshot: { sha256: 'c'.repeat(64), files: [{ path: 'a.conllu', sha256: 'd'.repeat(64), size: 10 }] }, memoryLimitEnforced: true });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }

async function fixture(era: 'modern' | 'legacy', action: (input: { root: string; workspace: string; client: Client; raw: Record<string, unknown>[]; failProgress: (callback: (value: Record<string, unknown>) => Promise<void>) => void }) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-public-progress-'))), workspace = path.join(root, 'workspace');
  await mkdir(workspace); await writeFile(path.join(workspace, 'a.conllu'), 'unchanged\n'); calls.stateRoot = path.join(root, 'state');
  calls.check.mockReset().mockResolvedValue(environment()); calls.setup.mockReset().mockResolvedValue(environment()); calls.run.mockReset().mockResolvedValue(workerResult()); calls.release.mockReset().mockResolvedValue(undefined);
  const client = new Client({ name: 'progress-' + era, version: '1' }, { versionNegotiation: era === 'modern' ? { mode: { pin: '2026-07-28' } } : { mode: 'legacy' } });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair(), raw: Record<string, unknown>[] = [];
  let progressFailure: ((value: Record<string, unknown>) => Promise<void>) | undefined;
  const send = serverTransport.send.bind(serverTransport);
  serverTransport.send = async (...args: Parameters<typeof send>) => { const message = args[0] as Record<string, unknown>; if (message.method === 'notifications/progress') { const value = message.params as Record<string, unknown>; raw.push(value); await progressFailure?.(value); } await send(...args); };
  const serving = serveStdio(() => createServer(process.cwd(), undefined, [root]), { transport: serverTransport });
  try { await client.connect(clientTransport); await action({ root, workspace, client, raw, failProgress: callback => { progressFailure = callback; } }); }
  finally { await client.close(); await serving.close(); await rm(root, { recursive: true, force: true }); }
}

test.each(['modern', 'legacy'] as const)('%s read-only readiness emits requested progress without creating state, including unready outcomes', era => fixture(era, async ({ root, client }) => {
  calls.check.mockResolvedValue(environment(false)); const before = await readdir(root), progress: Progress[] = [];
  const result = await client.callTool({ name: 'check_ud_environment', arguments: {} }, { onprogress: value => progress.push(value) });
  expect(result.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { ready: false } });
  expect(progress).toEqual([{ progress: 0, total: 4, message: 'Checking local runtime readiness' }, { progress: 4, total: 4, message: 'Readiness inquiry completed' }]);
  expect(await readdir(root)).toEqual(before);
}));

test.each(['modern', 'legacy'] as const)('%s setup reports preparation before its result and completes after saving verified selection', era => fixture(era, async ({ client }) => {
  const gate = deferred<Record<string, unknown>>(), started = deferred<void>(), progress: Progress[] = [];
  calls.setup.mockImplementation(async () => { started.resolve(); return gate.promise; });
  const pending = client.callTool({ name: 'setup_ud_environment', arguments: { engine: 'docker' } }, { onprogress: value => progress.push(value) });
  await started.promise; expect(progress.map(value => value.progress)).toEqual([0, 1]);
  gate.resolve(environment()); const result = await pending;
  expect(result.structuredContent).toMatchObject({ result: { ready: true, runtime: { engine: 'docker' } } });
  expect(progress.map(value => value.progress)).toEqual([0, 1, 2, 3, 4]);
  expect(progress.at(-1)).toEqual({ progress: 4, total: 4, message: 'Runtime preparation completed' });
  expect(JSON.parse(await readFile(calls.stateRoot + '-selection/selected.json', 'utf8'))).toMatchObject({ engine: 'docker' });
}));

test.each(['modern', 'legacy'] as const)('%s domain calls bind monotonic progress to each requested token and emit nothing for an unrequested token', era => fixture(era, async ({ workspace, client, raw }) => {
  const first: Progress[] = [], second: Progress[] = [], args = { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' };
  await Promise.all([client.callTool({ name: 'treebank_profile', arguments: args }, { onprogress: value => first.push(value) }), client.callTool({ name: 'treebank_profile', arguments: args }, { onprogress: value => second.push(value) })]);
  for (const events of [first, second]) expect(events.map(value => [value.progress, value.total])).toEqual([[0, 4], [2, 4], [3, 4], [4, 4]]);
  const tokens = [...new Set(raw.map(value => value.progressToken))]; expect(tokens).toHaveLength(2);
  for (const token of tokens) expect(raw.filter(value => value.progressToken === token).map(value => value.progress)).toEqual([0, 2, 3, 4]);
  raw.length = 0; await client.callTool({ name: 'treebank_profile', arguments: args }); expect(raw).toEqual([]);
}));

test.each(['modern', 'legacy'] as const)('%s preserves caller-supplied string progress tokens and keeps blocked operations below completion', era => fixture(era, async ({ workspace, client, raw }) => {
  client.setNotificationHandler('notifications/progress', () => {}); calls.check.mockResolvedValue(environment(false));
  const result = await client.callTool({ name: 'treebank_profile', arguments: { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, _meta: { progressToken: 'explicit-request-token' } });
  expect(result.isError).toBe(true); expect(raw).toEqual([{ progressToken: 'explicit-request-token', progress: 0, total: 4, message: 'Checking local runtime readiness' }]);
  expect(calls.run).not.toHaveBeenCalled();
}));

test.each(['modern', 'legacy'] as const)('%s completes operation progress for a complete linguistic rejection rather than treating it as an execution failure', era => fixture(era, async ({ workspace, client }) => {
  calls.run.mockResolvedValue({ ...workerResult(), result: { passed: false, incidents: [{ testid: 'non-unique-sent-id', message: 'Explicit invalid-corpus fixture' }], scope: { file_paths: ['a.conllu'], sentence_only: false }, coverage: { content: 'completed' }, limitations: [] } });
  const progress: Progress[] = [];
  const result = await client.callTool({ name: 'validation_report', arguments: { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '', options: { language_code: 'en' } } }, { onprogress: value => progress.push(value) });
  expect(result.isError).not.toBe(true); expect(result.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { passed: false }, diagnostics: [{ testid: 'non-unique-sent-id' }] });
  expect(progress.map(value => value.progress)).toEqual([0, 2, 3, 4]);
}));

test.each(['modern', 'legacy'] as const)('%s cancelled work never emits terminal progress while owned cleanup remains pending', era => fixture(era, async ({ workspace, client, raw }) => {
  const started = deferred<void>(), aborted = deferred<void>(), cleanup = deferred<void>(), done = deferred<void>();
  calls.run.mockImplementation(async (input: { signal: AbortSignal }) => {
    started.resolve();
    try { await new Promise((_resolve, reject) => input.signal.addEventListener('abort', () => { aborted.resolve(); reject(new Error('WORKER_CANCELLED')); }, { once: true })); }
    finally { await cleanup.promise; done.resolve(); }
  });
  const controller = new AbortController(), progress: Progress[] = [];
  const pending = client.callTool({ name: 'treebank_profile', arguments: { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' } }, { signal: controller.signal, onprogress: value => progress.push(value) });
  const rejected = expect(pending).rejects.toThrow();
  try { await started.promise; controller.abort(); await aborted.promise; expect(progress.map(value => value.progress)).toEqual([0, 2, 3]); }
  finally { cleanup.resolve(); await done.promise; await rejected; }
  expect(raw.some(value => value.progress === 4)).toBe(false);
}));

test('cleanup failure rejects the operation before terminal progress and the internal observer sees only the settled result', () => fixture('legacy', async ({ root, workspace }) => {
  calls.check.mockResolvedValue({ ...environment(), runtime: { engine: 'userspace' } }); calls.release.mockRejectedValue(new Error('OWNED_RELEASE_FAILED'));
  const contract = loadContracts(process.cwd()).domain.find(value => value.name === 'treebank_profile')!, progress: number[] = [], observations: unknown[] = [];
  const result = await executeOperation(contract, { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, loadContracts(process.cwd()).domain, { sourceRoot: process.cwd(), allowedRoots: [root], userspaceStateRoot: calls.stateRoot }, undefined, { progress: async value => { progress.push(value); }, observe: value => observations.push(value) });
  expect(result).toMatchObject({ isError: true, structuredContent: { execution: { status: 'rejected' }, result: { reason: 'OWNED_RELEASE_FAILED' } } });
  expect(progress).toEqual([0, 2, 3]); expect(observations).toEqual([{ type: 'tool_call', name: 'treebank_profile' }, { type: 'tool_result', name: 'treebank_profile', execution: result.structuredContent.execution, provenance: result.structuredContent.provenance }]);
}));

test('dry-run setup stays read-only and failed setup never reports terminal success', () => fixture('legacy', async ({ root, client, raw }) => {
  const before = await readdir(root); calls.setup.mockResolvedValue({ ...environment(false), status: 'setup_needed', dry_run: true });
  const progress: Progress[] = []; await client.callTool({ name: 'setup_ud_environment', arguments: { dry_run: true } }, { onprogress: value => progress.push(value) });
  expect(progress.map(value => value.message)).toEqual(['Checking runtime setup prerequisites', 'Assessing local runtime setup', 'Setup assessment completed']);
  expect(await readdir(root)).toEqual(before);
  calls.setup.mockResolvedValue({ ...environment(false), status: 'failed' }); raw.length = 0;
  const failed = await client.callTool({ name: 'setup_ud_environment', arguments: {} }, { onprogress: () => {} });
  expect(failed.isError).toBe(true); expect(raw.map(value => value.progress)).toEqual([0, 1]);
}));

test('an unavailable advisory progress channel does not prevent work or alter the final observed outcome', () => fixture('legacy', async ({ root, workspace }) => {
  const contract = loadContracts(process.cwd()).domain.find(value => value.name === 'treebank_profile')!, observations: unknown[] = [];
  const notify = vi.fn(async () => { throw new Error('PROGRESS_DELIVERY_FAILED'); });
  const result = await executeOperation(contract, { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, loadContracts(process.cwd()).domain, { sourceRoot: process.cwd(), allowedRoots: [root], userspaceStateRoot: calls.stateRoot }, undefined, { progress: notify, observe: value => observations.push(value) });
  expect(result.isError).not.toBe(true); expect(result.structuredContent.execution.status).toBe('completed'); expect(notify).toHaveBeenCalledOnce();
  expect(observations).toHaveLength(2); expect(observations.at(-1)).toMatchObject({ type: 'tool_result', execution: { status: 'completed' } });
}));

test.each(['modern', 'legacy'] as const)('%s rejected terminal progress preserves the successful real broker export and never repeats work', era => fixture(era, async ({ workspace, client, failProgress }) => {
  const output = path.join(workspace, 'exported.svg'), bytes = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg">observable export</svg>\n');
  calls.run.mockResolvedValue({ ...workerResult(), result: { status: 'complete', output_path: output, requires_broker_export: true, artifacts: [{ relative_path: 'preview.svg', mime_type: 'image/svg+xml', content_base64: bytes.toString('base64'), size_bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }], coverage: { basic_dependencies: 'drawn', multiword_rows_not_drawn: 0, empty_nodes_not_drawn: 0, enhanced_edges_not_drawn: false, sent_id: null }, limitations: [] } });
  let observedBeforeRejection: Buffer | undefined;
  failProgress(async value => { if (value.progress === 4) { observedBeforeRejection = await readFile(output); throw new Error('Notification rejected after publication'); } });
  const progress: Progress[] = [];
  const result = await client.callTool({ name: 'sentence_render', arguments: { working_tree_path: workspace, sentence_conllu: '# text = A\n1\tA\t_\tX\t_\t_\t0\troot\t_\t_\n\n', output_format: 'svg', output_path: output, ud_context_path: '' } }, { onprogress: value => progress.push(value) });
  expect(result.isError, JSON.stringify(result)).not.toBe(true); expect(result.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { export_transaction: { status: 'completed' }, requires_broker_export: false } });
  expect(observedBeforeRejection).toEqual(bytes); expect(await readFile(output)).toEqual(bytes); expect(await readFile(path.join(workspace, 'a.conllu'), 'utf8')).toBe('unchanged\n');
  expect(progress.map(value => value.progress)).toEqual([0, 2, 3]); expect(calls.run).toHaveBeenCalledOnce();
}));

test.each(['modern', 'legacy'] as const)('%s continuation progress belongs only to an actively waiting request and rebinds on resume', era => fixture(era, async ({ workspace, client, raw }) => {
  client.setNotificationHandler('notifications/progress', () => {});
  const started = deferred<void>(), worker = deferred<ReturnType<typeof workerResult>>(); calls.run.mockImplementation(async () => { started.resolve(); return worker.promise; });
  const args = { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, key = 'io.github.mehmetoguzderin/ud-agent/continuation';
  try {
    const pending = await client.callTool({ name: 'treebank_profile', arguments: args, _meta: { progressToken: 'first-request', [key]: { budget_ms: 1 } } });
    expect(pending.structuredContent).toMatchObject({ execution: { status: 'incomplete' }, result: { status: 'pending' } });
    const initialCount = raw.filter(value => value.progressToken === 'first-request').length;
    await started.promise; expect(raw.filter(value => value.progressToken === 'first-request')).toHaveLength(initialCount);
    const token = (pending.structuredContent!.result as { continuation_token: string }).continuation_token;
    const resumed = client.callTool({ name: 'treebank_profile', arguments: args, _meta: { progressToken: 'resumed-request', [key]: { token, budget_ms: 5000 } } });
    await vi.waitFor(() => expect(raw.some(value => value.progressToken === 'resumed-request' && value.progress === 3)).toBe(true));
    worker.resolve(workerResult()); const completed = await resumed;
    expect(completed.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { sentence_count: 1 } });
    expect(raw.filter(value => value.progressToken === 'first-request')).toHaveLength(initialCount);
    expect(raw.filter(value => value.progressToken === 'resumed-request').map(value => value.progress)).toEqual([3, 4]);
    expect(calls.run).toHaveBeenCalledOnce();
  } finally { worker.resolve(workerResult()); }
}));

test.each(['modern', 'legacy'] as const)('%s concurrent resume/cancel requests share cleanup but never restore a returned request token', era => fixture(era, async ({ workspace, client, raw }) => {
  client.setNotificationHandler('notifications/progress', () => {});
  const started = deferred<void>(), aborted = deferred<void>(), cleanup = deferred<void>();
  calls.run.mockImplementation(async (input: { signal: AbortSignal }) => { started.resolve(); try { await new Promise((_resolve, reject) => input.signal.addEventListener('abort', () => { aborted.resolve(); reject(new Error('WORKER_CANCELLED')); }, { once: true })); } finally { await cleanup.promise; } });
  const args = { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, key = 'io.github.mehmetoguzderin/ud-agent/continuation';
  try {
    const pending = await client.callTool({ name: 'treebank_profile', arguments: args, _meta: { progressToken: 'returned-request', [key]: { budget_ms: 1 } } });
    const token = (pending.structuredContent!.result as { continuation_token: string }).continuation_token, returnedCount = raw.filter(value => value.progressToken === 'returned-request').length;
    await started.promise;
    const resumed = client.callTool({ name: 'treebank_profile', arguments: args, _meta: { progressToken: 'active-resume', [key]: { token, budget_ms: 5000 } } });
    await vi.waitFor(() => expect(raw.some(value => value.progressToken === 'active-resume')).toBe(true));
    const cancelled = client.callTool({ name: 'treebank_profile', arguments: args, _meta: { progressToken: 'active-cancel', [key]: { token, cancel: true, budget_ms: 5000 } } });
    await aborted.promise; expect(raw.some(value => value.progress === 4)).toBe(false); cleanup.resolve();
    for (const result of await Promise.all([resumed, cancelled])) expect(result).toMatchObject({ isError: true, structuredContent: { result: { code: 'WORKER_CANCELLED' } } });
    expect(raw.filter(value => value.progressToken === 'returned-request')).toHaveLength(returnedCount);
    expect(calls.run).toHaveBeenCalledOnce();
  } finally { cleanup.resolve(); }
}));

test('cancelling a stalled advisory delivery releases an acquired lease before any worker is launched', () => fixture('legacy', async ({ root, workspace }) => {
  calls.check.mockResolvedValue({ ...environment(), runtime: { engine: 'userspace' } });
  const entered = deferred<void>(), controller = new AbortController(), contract = loadContracts(process.cwd()).domain.find(value => value.name === 'treebank_profile')!;
  const pending = executeOperation(contract, { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, loadContracts(process.cwd()).domain, { sourceRoot: process.cwd(), allowedRoots: [root], userspaceStateRoot: calls.stateRoot }, controller.signal, { progress: async phase => { if (phase === 3) { entered.resolve(); await new Promise<void>(() => {}); } } });
  await entered.promise; controller.abort(); const result = await pending;
  expect(result).toMatchObject({ isError: true, structuredContent: { result: { code: 'WORKER_CANCELLED' } } });
  expect(calls.run).not.toHaveBeenCalled(); expect(calls.release).toHaveBeenCalledOnce();
}));

test('an unresponsive advisory channel is bounded and cannot retain a completed operation lease', () => fixture('legacy', async ({ root, workspace }) => {
  calls.check.mockResolvedValue({ ...environment(), runtime: { engine: 'userspace' } });
  const entered = deferred<void>(), controller = new AbortController(), contract = loadContracts(process.cwd()).domain.find(value => value.name === 'treebank_profile')!;
  const pending = executeOperation(contract, { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, loadContracts(process.cwd()).domain, { sourceRoot: process.cwd(), allowedRoots: [root], userspaceStateRoot: calls.stateRoot }, controller.signal, { progress: async phase => { if (phase === 3) { entered.resolve(); await new Promise<void>(() => {}); } } });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // The delivery bound starts at the blocked channel, after native state setup.
    await Promise.race([entered.promise, pending.then(() => { throw new Error('Operation ended before reaching advisory delivery.'); })]);
    const outcome = await Promise.race([pending, new Promise<'deadline'>(resolve => { timer = setTimeout(() => resolve('deadline'), process.platform === 'win32' ? 15_000 : 1500); })]);
    expect(outcome).not.toBe('deadline'); expect(outcome).toMatchObject({ structuredContent: { execution: { status: 'completed' } } });
    expect(calls.release).toHaveBeenCalledOnce();
  } finally { if (timer) clearTimeout(timer); controller.abort(); await pending; }
}), process.platform === 'win32' ? 60_000 : 30_000);

test('late settlement of an issued notification cannot change a completed outcome or reacquire its lease', () => fixture('legacy', async ({ root, workspace }) => {
  calls.check.mockResolvedValue({ ...environment(), runtime: { engine: 'userspace' } });
  const contract = loadContracts(process.cwd()).domain.find(value => value.name === 'treebank_profile')!, gate = deferred<void>(), delivered = deferred<void>(), phases: number[] = [];
  const result = await executeOperation(contract, { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '' }, loadContracts(process.cwd()).domain, { sourceRoot: process.cwd(), allowedRoots: [root], userspaceStateRoot: calls.stateRoot }, undefined, { progress: async phase => { if (phase === 3) { await gate.promise; phases.push(phase); delivered.resolve(); } else phases.push(phase); } });
  expect(result.structuredContent.execution.status).toBe('completed'); expect(calls.release).toHaveBeenCalledOnce(); expect(phases).toEqual([0, 2]);
  gate.resolve(); await delivered.promise;
  expect(phases).toEqual([0, 2, 3]); expect(result.structuredContent.execution.status).toBe('completed'); expect(calls.run).toHaveBeenCalledOnce(); expect(calls.release).toHaveBeenCalledOnce();
}));
