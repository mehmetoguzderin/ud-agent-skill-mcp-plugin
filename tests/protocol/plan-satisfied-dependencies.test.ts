/** Public MCP dispatch, real snapshot/worker plan handler/native transaction;
 * engine readiness and linguistic validation are explicit fixture providers. */
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, test, vi } from 'vitest';
import { captureOperationSnapshot } from '../../packages/workspace/src/input-broker.js';
import { verifySnapshotIntegrity } from '../../packages/workspace/src/snapshot.js';
import { sha256 } from '../../packages/workspace/src/journal.js';
const calls = vi.hoisted(() => ({ state: '', contextSha: 'b'.repeat(64), run: vi.fn(), afterWorker: undefined as undefined | (() => Promise<void>), duringValidation: undefined as undefined | (() => Promise<void>), alterResult: undefined as undefined | ((value: Record<string, unknown>) => Record<string, unknown>), planRuns: 0 }));
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
vi.mock('../../packages/runtime-manager/src/userspace.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/userspace.js')>(), userspaceStateRoot: () => calls.state }));
vi.mock('../../packages/runtime-manager/src/environment.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/environment.js')>(), checkEnvironment: async () => ({ ready: true, status: 'ready', runtime: { engine: 'docker', executable: '/explicit-fixture/docker' } }) }));
vi.mock('../../packages/coordinator/src/provider-runtime.js', () => ({ providerInspection: vi.fn(), providerReadiness: vi.fn(), setupProvider: vi.fn(), resolveAdmittedProvider: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), stateRoot: calls.state, image: { digest: 'sha256:' + 'a'.repeat(64), contextSha256: 'sha256:' + calls.contextSha }, run: (...args: unknown[]) => calls.run(...args) }) }));
vi.mock('../../packages/coordinator/src/docker-authority.js', async original => ({ ...await original<typeof import('../../packages/coordinator/src/docker-authority.js')>(), resolveProductGuard: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard') }) }));
// This fixture supplies an already-built native helper; state operations still execute it.
vi.mock('../../packages/runtime-manager/src/receipt.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/receipt.js')>(), loadNativeGuardReceipt: async () => ({ guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard') }) }));
import { createServer } from '../../packages/coordinator/src/server.js';

const python = path.resolve(process.env.UD_AGENT_PYTHON ?? process.env.UD_RELEASE_PYTHON ?? '.venv/bin/python');
const bridge = `import json,sys
sys.path.insert(0,sys.argv[1])
from ud_agent.domain.plans import plan_apply
from ud_agent.evidence import broker_evidence
p=json.loads(sys.argv[2])
with broker_evidence(p['evidence'],p['snapshot']):
 print(json.dumps(plan_apply(p['arguments']),ensure_ascii=False))
`;
const corpus = '# sent_id = selected\n1\tSelected\t_\tX\t_\t_\t0\troot\t_\t_\n\n';
type Action = Record<string, unknown>;
const create = (id: string, file: string, text: string, depends: string[] = []): Action => ({ id, type: 'create_file', file_path: file, content: text, before_sha256: null, after_sha256: sha256(text), depends_on: depends });
async function fixture(era: 'modern' | 'legacy', action: (context: { workspace: string; apply: (actions: Action[], ids?: string[], key?: string, root?: string) => Promise<Awaited<ReturnType<Client['callTool']>>> }) => Promise<void>) {
  const base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-plan-dependency-'))), workspace = path.join(base, 'bank'); await mkdir(workspace); calls.state = path.join(base, 'provider'); calls.contextSha = 'b'.repeat(64); calls.afterWorker = undefined; calls.duringValidation = undefined; calls.alterResult = undefined; calls.planRuns = 0;
  calls.run.mockReset().mockImplementation(async (input: { operation: string; arguments: Record<string, unknown>; allowedRoots: string[] }) => {
    if (input.operation === 'validation_report') { await calls.duringValidation?.(); return { result: { status: 'complete', passed: true } }; }
    expect(input.operation).toBe('plan_apply'); calls.planRuns++;
    const captured = await captureOperationSnapshot(guard, input.arguments, input.allowedRoots, undefined, undefined, input.operation);
    try {
      await verifySnapshotIntegrity(guard, captured.snapshot);
      const result = await promisify(execFile)(python, ['-I', '-B', '-c', bridge, path.resolve('workers/ud/src'), JSON.stringify({ evidence: captured.brokerEvidence, snapshot: captured.snapshot.sha256, arguments: { ...captured.arguments, working_tree_path: captured.snapshot.directory } })], { timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
      const decoded: unknown = JSON.parse(result.stdout); expect(decoded).toBeTypeOf('object');
      await calls.afterWorker?.();
      return { result: calls.alterResult ? calls.alterResult(decoded as Record<string, unknown>) : decoded, snapshot: { sha256: captured.snapshot.sha256, files: captured.snapshot.files, root_identity: captured.snapshot.root_identity, source_map: captured.sourceMap } };
    } finally { await captured.snapshot.cleanup(); }
  });
  const client = new Client({ name: 'plan-proof-' + era, version: '1' }, { versionNegotiation: era === 'modern' ? { mode: { pin: '2026-07-28' } } : { mode: 'legacy' } }), [a, b] = InMemoryTransport.createLinkedPair();
  const serving = serveStdio(() => createServer(process.cwd(), undefined, [base]), { transport: b });
  try {
    await client.connect(a);
    await action({ workspace, apply: async (actions, ids = ['selected'], key = 'proof', root = workspace) => {
      await writeFile(path.join(root, 'plan.json'), JSON.stringify({ schema_version: 'ud-plan-v1', actions }));
      return client.callTool({ name: 'plan_apply', arguments: { working_tree_path: root, plan_path: 'plan.json', selected_action_ids: ids, options: { mode: 'apply', idempotency_key: key, validation_options: { language_code: 'en' } } } });
    } });
  } finally { await client.close(); await serving.close(); await rm(base, { recursive: true, force: true }); }
}

test.each(['modern', 'legacy'] as const)('%s proves a present non-corpus dependency and applies only the selected action', era => fixture(era, async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'dependency.txt'), 'already complete\r\n');
  const actions = [create('prerequisite', 'dependency.txt', 'already complete\r\n'), create('unrelated', 'never.txt', 'unselected'), create('selected', 'result.conllu', corpus, ['prerequisite'])];
  const response = await apply(actions);
  expect(response.isError, JSON.stringify(response)).not.toBe(true);
  expect(response.structuredContent).toMatchObject({ result: { details: { selected_action_ids: ['selected'], satisfied_action_ids: ['prerequisite'] }, transaction: { status: 'completed', files: [{ path: 'result.conllu', before_sha256: null, after_sha256: sha256(corpus) }] } } });
  expect(await readFile(path.join(workspace, 'dependency.txt'), 'utf8')).toBe('already complete\r\n'); expect(await readFile(path.join(workspace, 'result.conllu'), 'utf8')).toBe(corpus);
  await expect(readFile(path.join(workspace, 'never.txt'))).rejects.toMatchObject({ code: 'ENOENT' }); expect(calls.planRuns).toBe(1);
}), 60000);

test.each(['modern', 'legacy'] as const)('%s uses explicit absence for deleted dependencies and rejects absent required content', era => fixture(era, async ({ workspace, apply }) => {
  const deletion = { id: 'prerequisite', type: 'delete_file', file_path: 'gone.txt', before_sha256: sha256('old'), after_sha256: null, depends_on: [] };
  const response = await apply([deletion, create('selected', 'result.txt', 'selected only', ['prerequisite'])]);
  expect(response.isError, JSON.stringify(response)).not.toBe(true); expect(await readFile(path.join(workspace, 'result.txt'), 'utf8')).toBe('selected only');
  const failed = await apply([create('prerequisite', 'missing.txt', 'required'), create('selected', 'other.txt', 'forbidden', ['prerequisite'])], ['selected'], 'absent');
  expect(failed.isError).toBe(true); expect(JSON.stringify(failed)).toContain('PLAN_DEPENDENCY_NOT_SATISFIED'); await expect(readFile(path.join(workspace, 'other.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test.each(['modern', 'legacy'] as const)('%s rejects proof becoming stale before the broker recaptures inputs', era => fixture(era, async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'dependency.txt'), 'complete'); calls.afterWorker = () => writeFile(path.join(workspace, 'dependency.txt'), 'concurrent external edit');
  const response = await apply([create('prerequisite', 'dependency.txt', 'complete'), create('selected', 'result.txt', 'forbidden', ['prerequisite'])]);
  expect(response.isError).toBe(true); expect(JSON.stringify(response)).toContain('PLAN_DEPENDENCY_NOT_SATISFIED');
  expect(await readFile(path.join(workspace, 'dependency.txt'), 'utf8')).toBe('concurrent external edit'); await expect(readFile(path.join(workspace, 'result.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test.each(['present', 'absent'] as const)('commit-time revalidation rejects a %s dependency changed during candidate validation', kind => fixture('modern', async ({ workspace, apply }) => {
  if (kind === 'present') await writeFile(path.join(workspace, 'dependency.txt'), 'complete');
  const dependency = kind === 'present' ? create('prerequisite', 'dependency.txt', 'complete') : { id: 'prerequisite', type: 'delete_file', file_path: 'dependency.txt', before_sha256: sha256('old'), after_sha256: null, depends_on: [] };
  calls.duringValidation = () => writeFile(path.join(workspace, 'dependency.txt'), 'external bytes during validator');
  const response = await apply([dependency, create('selected', 'result.conllu', corpus, ['prerequisite'])]);
  expect(response.isError).toBe(true); expect(JSON.stringify(response)).toContain('STALE_DEPENDENCY_PRECONDITION');
  expect(await readFile(path.join(workspace, 'dependency.txt'), 'utf8')).toBe('external bytes during validator'); await expect(readFile(path.join(workspace, 'result.conllu'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test('public apply rejects unsupported dependency postconditions without applying any action', () => fixture('legacy', async ({ workspace, apply }) => {
  for (const dependency of [{ id: 'prerequisite', type: 'prepare_context', depends_on: [] }, { id: 'prerequisite', type: 'replace_text', file_path: 'dependency.txt', before_sha256: sha256('old'), old_text: 'old', new_text: 'new', depends_on: [] }]) {
    const response = await apply([dependency, create('selected', 'result.txt', 'forbidden', ['prerequisite'])]);
    expect(response.isError).toBe(true); expect(JSON.stringify(response)).toContain('POSTCONDITION_UNPROVABLE');
  }
  expect(calls.planRuns).toBe(2); await expect(readFile(path.join(workspace, 'result.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test('caller-authored unchanged-file structural and text postconditions cannot certify an unperformed dependency', () => fixture('modern', async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'dependency.conllu'), corpus);
  const forged = [
    { id: 'prerequisite', type: 'replace_text', file_path: 'dependency.conllu', before_sha256: sha256('historical bytes'), old_text: 'old', new_text: 'new', after_sha256: sha256(corpus), depends_on: [] },
    { id: 'prerequisite', type: 'token_split', arguments: { token_ref: { tree_ref: { file_path: 'dependency.conllu', sent_id: 'selected' }, token_id: '1' }, replacement_words: ['Selected', 'split'] }, postconditions: { 'dependency.conllu': sha256(corpus) }, depends_on: [] },
  ];
  for (const dependency of forged) {
    const response = await apply([dependency, create('selected', 'result.txt', 'forbidden', ['prerequisite'])]);
    expect(response.isError).toBe(true); expect(JSON.stringify(response)).toContain('POSTCONDITION_UNPROVABLE');
  }
  expect(await readFile(path.join(workspace, 'dependency.conllu'), 'utf8')).toBe(corpus);
  await expect(readFile(path.join(workspace, 'result.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test('public apply derives satisfied replacement and rename effects and leaves their files untouched', () => fixture('modern', async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'replacement.txt'), 'final replacement\r\n'); await writeFile(path.join(workspace, 'renamed.txt'), 'exact renamed bytes');
  await writeFile(path.join(workspace, 'rewritten.txt'), 'rewritten renamed bytes');
  const replacement = { id: 'replacement', type: 'replace_file', file_path: 'replacement.txt', before_sha256: sha256('historical input'), after_sha256: sha256('final replacement\r\n'), content: 'final replacement\r\n', depends_on: [] };
  const rename = { id: 'rename', type: 'rename_file', source: 'old.txt', destination: 'renamed.txt', before_sha256: sha256('exact renamed bytes'), target_before_sha256: null, depends_on: ['replacement'] };
  const rewritten = { id: 'rename-content', type: 'rename_file', file_path: 'previous.txt', target_file_path: 'rewritten.txt', before_sha256: sha256('original rename bytes'), target_before_sha256: null, conflict: false, content: 'rewritten renamed bytes', after_sha256: sha256('rewritten renamed bytes'), depends_on: ['rename'] };
  const response = await apply([replacement, rename, rewritten, create('selected', 'result.txt', 'selected only', ['rename-content'])]);
  expect(response.isError, JSON.stringify(response)).not.toBe(true); expect(response.structuredContent).toMatchObject({ result: { details: { satisfied_action_ids: ['replacement', 'rename', 'rename-content'] }, transaction: { files: [{ path: 'result.txt' }] } } });
  expect(await readFile(path.join(workspace, 'replacement.txt'), 'utf8')).toBe('final replacement\r\n'); expect(await readFile(path.join(workspace, 'renamed.txt'), 'utf8')).toBe('exact renamed bytes'); await expect(readFile(path.join(workspace, 'old.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
  expect(await readFile(path.join(workspace, 'rewritten.txt'), 'utf8')).toBe('rewritten renamed bytes'); await expect(readFile(path.join(workspace, 'previous.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test('an idempotent public retry rechecks explicit absence instead of replaying stale success', () => fixture('legacy', async ({ workspace, apply }) => {
  const dependency = { id: 'prerequisite', type: 'delete_file', file_path: 'gone.txt', before_sha256: sha256('old'), after_sha256: null, depends_on: [] };
  const actions = [dependency, create('selected', 'result.txt', 'one application', ['prerequisite'])];
  const first = await apply(actions); expect(first.isError, JSON.stringify(first)).not.toBe(true);
  const replay = await apply(actions); expect(replay.isError, JSON.stringify(replay)).not.toBe(true); expect(replay.structuredContent).toMatchObject({ result: { replayed: true } }); expect(calls.planRuns).toBe(1);
  await writeFile(path.join(workspace, 'gone.txt'), 'new external file');
  const stale = await apply(actions); expect(stale.isError).toBe(true); expect(JSON.stringify(stale)).toContain('IDEMPOTENT_RESULT_STALE'); expect(calls.planRuns).toBe(1);
  expect(await readFile(path.join(workspace, 'gone.txt'), 'utf8')).toBe('new external file'); expect(await readFile(path.join(workspace, 'result.txt'), 'utf8')).toBe('one application');
}), 60000);

test('the host rejects worker attempts to apply an unselected action or replace the plan input', () => fixture('modern', async ({ workspace, apply }) => {
  for (const target of ['unselected.txt', 'plan.json']) {
    calls.alterResult = result => ({ ...result, file_operations: (result.file_operations as Record<string, unknown>[]).map(value => ({ ...value, file_path: target })) });
    const response = await apply([create('unselected', 'unselected.txt', 'never'), create('selected', 'result.txt', 'selected')], ['selected'], target);
    expect(response.isError).toBe(true); expect(JSON.stringify(response)).toContain('outside the authorized operation scope');
    await expect(readFile(path.join(workspace, 'result.txt'))).rejects.toMatchObject({ code: 'ENOENT' }); await expect(readFile(path.join(workspace, 'unselected.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
    expect(JSON.parse(await readFile(path.join(workspace, 'plan.json'), 'utf8')).actions).toHaveLength(2);
  }
}), 60000);

test('the host binds selected literal file effects and reports only independently proven dependency IDs', () => fixture('legacy', async ({ workspace, apply }) => {
  calls.alterResult = result => ({ ...result, details: { selected_action_ids: ['invented'], satisfied_action_ids: ['invented'] } });
  const good = await apply([create('selected', 'good.txt', 'literal selected bytes')]);
  expect(good.isError, JSON.stringify(good)).not.toBe(true); expect(good.structuredContent).toMatchObject({ result: { details: { selected_action_ids: ['selected'] } } });
  expect((good.structuredContent!.result as Record<string, unknown>).details).not.toHaveProperty('satisfied_action_ids');
  calls.alterResult = result => ({ ...result, file_operations: (result.file_operations as Record<string, unknown>[]).map(value => ({ ...value, content: 'substituted bytes', after_sha256: sha256('substituted bytes') })) });
  const changed = await apply([create('selected', 'wrong.txt', 'literal requested bytes')], ['selected'], 'altered');
  expect(changed.isError).toBe(true); expect(JSON.stringify(changed)).toContain('PLAN_SELECTED_EFFECT_MISMATCH');
  await expect(readFile(path.join(workspace, 'wrong.txt'))).rejects.toMatchObject({ code: 'ENOENT' }); expect(await readFile(path.join(workspace, 'good.txt'), 'utf8')).toBe('literal selected bytes');
}), 60000);

test('contradictory rename aliases and portable source/target collisions never admit alias writes', () => fixture('modern', async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'old.txt'), 'source'); await writeFile(path.join(workspace, 'victim.txt'), 'protected');
  for (const extra of [{ source: 'victim.txt' }, { destination: 'victim.txt' }, { target_file_path: 'OLD.TXT' }]) {
    calls.alterResult = result => ({ ...result, changes: [{ file_path: 'victim.txt', before_sha256: sha256('protected'), after_sha256: sha256('unrequested'), content: 'unrequested' }] });
    const action = { id: 'selected', type: 'rename_file', file_path: 'old.txt', target_file_path: 'new.txt', before_sha256: sha256('source'), target_before_sha256: null, depends_on: [], ...extra };
    const response = await apply([action], ['selected'], JSON.stringify(extra));
    expect(response.isError).toBe(true); expect(JSON.stringify(response)).toContain('PLAN_RENAME_ALIASES_CONFLICT');
    expect(await readFile(path.join(workspace, 'victim.txt'), 'utf8')).toBe('protected'); expect(await readFile(path.join(workspace, 'old.txt'), 'utf8')).toBe('source');
    await expect(readFile(path.join(workspace, 'new.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
  }
}), 60000);

function textBatch(): Action[] {
  return [{ id: 'left', type: 'replace_text', file_path: 'left.txt', before_sha256: sha256('old left'), old_text: 'old', new_text: 'new', depends_on: [] },
    { id: 'right', type: 'replace_text', file_path: 'right.txt', before_sha256: sha256('old right'), old_text: 'old', new_text: 'new', depends_on: [] },
    create('selected', 'result.txt', 'selected only', ['left'])];
}
async function originalBatchRecord(): Promise<{ file: string; value: Record<string, any> }> {
  const state = calls.state + '-transactions';
  for (const name of await readdir(state)) if (/^\.request-[a-f0-9]{64}\.json$/.test(name)) {
    const file = path.join(state, name), value = JSON.parse(await readFile(file, 'utf8'));
    if (JSON.stringify(value.plan_completion?.action_ids) === JSON.stringify(['left', 'right'])) return { file, value };
  }
  throw new Error('Expected host-issued batch receipt was absent');
}

test('a validated completed text batch proves a member dependency only while the complete batch outputs remain current', () => fixture('modern', async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'left.txt'), 'old left'); await writeFile(path.join(workspace, 'right.txt'), 'old right');
  const actions = textBatch(), committed = await apply(actions, ['left', 'right'], 'batch');
  expect(committed.isError, JSON.stringify(committed)).not.toBe(true);
  const { value } = await originalBatchRecord(); expect(value.plan_completion).toMatchObject({ action_ids: ['left', 'right'], validation: 'passed', outputs: [{ path: 'left.txt', sha256: sha256('new left') }, { path: 'right.txt', sha256: sha256('new right') }] });
  const dependent = await apply(actions, ['selected'], 'dependent'); expect(dependent.isError, JSON.stringify(dependent)).not.toBe(true);
  expect(await readFile(path.join(workspace, 'result.txt'), 'utf8')).toBe('selected only'); expect(await readFile(path.join(workspace, 'left.txt'), 'utf8')).toBe('new left'); expect(await readFile(path.join(workspace, 'right.txt'), 'utf8')).toBe('new right');
  await writeFile(path.join(workspace, 'right.txt'), 'externally changed batch sibling');
  const stale = await apply(actions, ['selected'], 'stale-batch'); expect(stale.isError).toBe(true); expect(JSON.stringify(stale)).toContain('POSTCONDITION_UNPROVABLE');
}), 60000);

test('batch receipt tampering, cross-workspace copies and legacy absence never authorize text dependencies', () => fixture('legacy', async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'left.txt'), 'old left'); await writeFile(path.join(workspace, 'right.txt'), 'old right');
  const actions = textBatch(), committed = await apply(actions, ['left', 'right'], 'batch'); expect(committed.isError, JSON.stringify(committed)).not.toBe(true);
  const { file, value } = await originalBatchRecord();
  for (const [field, forged] of [['actions_sha256', 'f'.repeat(64)], ['snapshot_sha256', 'e'.repeat(64)], ['request_hash', 'd'.repeat(64)], ['action_ids', ['left']]] as const) {
    await writeFile(file, JSON.stringify({ ...value, plan_completion: { ...value.plan_completion, [field]: forged } }));
    const failed = await apply(actions, ['selected'], 'tamper-' + field); expect(failed.isError).toBe(true); expect(JSON.stringify(failed)).toContain('PLAN_COMPLETION_INVALID');
    await writeFile(file, JSON.stringify(value));
  }
  const journalPath = path.join(calls.state + '-transactions', 'transactions', value.plan_completion.transaction_id, 'journal.json'), journalBytes = await readFile(journalPath, 'utf8'), changedJournal = JSON.parse(journalBytes);
  delete changedJournal.read_preconditions; await writeFile(journalPath, JSON.stringify(changedJournal));
  const unbound = await apply(actions, ['selected'], 'tamper-journal-conditions'); expect(unbound.isError).toBe(true); expect(JSON.stringify(unbound)).toContain('PLAN_COMPLETION_INVALID'); await writeFile(journalPath, journalBytes);
  const other = path.join(path.dirname(workspace), 'other-bank'); await mkdir(other); await writeFile(path.join(other, 'left.txt'), 'new left'); await writeFile(path.join(other, 'right.txt'), 'new right');
  const foreign = await apply(actions, ['selected'], 'foreign', other); expect(foreign.isError).toBe(true); expect(JSON.stringify(foreign)).toContain('POSTCONDITION_UNPROVABLE');
  const legacy = { ...value }; delete legacy.plan_completion; await writeFile(file, JSON.stringify(legacy));
  const absent = await apply(actions, ['selected'], 'legacy'); expect(absent.isError).toBe(true); expect(JSON.stringify(absent)).toContain('POSTCONDITION_UNPROVABLE');
  await expect(readFile(path.join(workspace, 'result.txt'))).rejects.toMatchObject({ code: 'ENOENT' }); await expect(readFile(path.join(other, 'result.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test('context satisfaction requires the exact host-published resource and rejects its later removal', () => fixture('modern', async ({ workspace, apply }) => {
  const families = { 'data.json': 'auxiliaries', 'deprels.json': 'deprels', 'edeprels.json': 'edeprels', 'feats.json': 'features', 'tospace.json': 'expressions', 'udeprels.json': 'udeprels', 'upos.json': 'upos' };
  const files = Object.fromEntries(Object.entries(families).map(([file, family]) => [file, JSON.stringify({ [family]: { en: [] } })]));
  const hashes = Object.fromEntries(Object.entries(files).map(([file, text]) => [file, sha256(text)])), base = Object.fromEntries(Object.keys(families).map(file => [file, sha256('base ' + file)]));
  calls.contextSha = sha256(JSON.stringify(base));
  const context = { id: 'context', type: 'prepare_context', language_code: 'en', files, file_hashes: hashes, base_hashes: base, context_sha256: sha256(JSON.stringify(hashes)), depends_on: [] };
  const actions = [context, create('selected', 'result.txt', 'context publication consumed', ['context'])];
  const published = await apply(actions, ['context'], 'publish'); expect(published.isError, JSON.stringify(published)).not.toBe(true);
  const references = (published.structuredContent!.result as Record<string, unknown>).prepared_contexts as { uri: string; context_sha256: string }[];
  expect(references).toHaveLength(1); expect(references[0]!.context_sha256).toBe(context.context_sha256);
  const dependent = await apply(actions, ['selected'], 'context-dependent'); expect(dependent.isError, JSON.stringify(dependent)).not.toBe(true); expect(await readFile(path.join(workspace, 'result.txt'), 'utf8')).toBe('context publication consumed');
  const resourceFile = path.join(calls.state + '-resources', new URL(references[0]!.uri).pathname.slice(1), 'data');
  await rm(resourceFile);
  const stale = await apply(actions, ['selected'], 'missing-publication'); expect(stale.isError).toBe(true); expect(JSON.stringify(stale)).toContain('POSTCONDITION_UNPROVABLE');
}), 60000);

test('a composed structural batch receipt admits a member only against the complete shared-file final output', () => fixture('legacy', async ({ workspace, apply }) => {
  const original = '# sent_id = a\n# text = cannot\n1\tcannot\t_\tX\t_\t_\t0\troot\t_\t_\n\n# sent_id = b\n# text = willnot\n1\twillnot\t_\tX\t_\t_\t0\troot\t_\t_\n\n';
  await writeFile(path.join(workspace, 'sentences.conllu'), original);
  const row = (id: string, form: string, head: string, relation: string) => ({ id, kind: 'word', form, lemma: '_', upos: 'X', xpos: '_', feats: {}, head, deprel: relation, deps: [{ head_id: head, deprel: relation }], misc: {} });
  const split = (id: string, sent: string, first: string): Action => ({ id, type: 'token_split', depends_on: [], input_fingerprints: { 'sentences.conllu': sha256(original) }, arguments: { token_ref: { tree_ref: { file_path: 'sentences.conllu', sent_id: sent }, token_id: '1' }, replacement_words: [first, 'not'], annotation_map: { id_mapping: { [sent + '#1']: [sent + '#$one', sent + '#$two'] }, sentences: [{ sent_id: sent, text: first + ' not', comments: [], rows: [row('$one', first, '0', 'root'), row('$two', 'not', '$one', 'advmod')] }] } } });
  const actions = [split('left', 'a', 'can'), split('right', 'b', 'will'), create('selected', 'result.txt', 'only selected after structural completion', ['left'])];
  const committed = await apply(actions, ['left', 'right'], 'structural-batch'); expect(committed.isError, JSON.stringify(committed)).not.toBe(true);
  const final = '# sent_id = a\n# text = can not\n1\tcan\t_\tX\t_\t_\t0\troot\t0:root\t_\n2\tnot\t_\tX\t_\t_\t1\tadvmod\t1:advmod\t_\n\n# sent_id = b\n# text = will not\n1\twill\t_\tX\t_\t_\t0\troot\t0:root\t_\n2\tnot\t_\tX\t_\t_\t1\tadvmod\t1:advmod\t_\n\n';
  expect(await readFile(path.join(workspace, 'sentences.conllu'), 'utf8')).toBe(final);
  const dependent = await apply(actions, ['selected'], 'after-structural'); expect(dependent.isError, JSON.stringify(dependent)).not.toBe(true);
  expect(await readFile(path.join(workspace, 'sentences.conllu'), 'utf8')).toBe(final); expect(await readFile(path.join(workspace, 'result.txt'), 'utf8')).toBe('only selected after structural completion');
}), 60000);

test('publishing a context cannot certify suppressed selected text effects', () => fixture('modern', async ({ workspace, apply }) => {
  await writeFile(path.join(workspace, 'left.txt'), 'old left');
  const families = { 'data.json': 'auxiliaries', 'deprels.json': 'deprels', 'edeprels.json': 'edeprels', 'feats.json': 'features', 'tospace.json': 'expressions', 'udeprels.json': 'udeprels', 'upos.json': 'upos' };
  const files = Object.fromEntries(Object.entries(families).map(([file, family]) => [file, JSON.stringify({ [family]: { en: [] } })]));
  const hashes = Object.fromEntries(Object.entries(files).map(([file, text]) => [file, sha256(text)])), base = Object.fromEntries(Object.keys(families).map(file => [file, sha256('base ' + file)]));
  calls.contextSha = sha256(JSON.stringify(base));
  const context = { id: 'context', type: 'prepare_context', language_code: 'en', files, file_hashes: hashes, base_hashes: base, context_sha256: sha256(JSON.stringify(hashes)), depends_on: [] };
  const rewrite = { id: 'rewrite', type: 'replace_text', file_path: 'left.txt', before_sha256: sha256('old left'), old_text: 'old', new_text: 'new', depends_on: [] };
  const actions = [context, rewrite, create('selected', 'result.txt', 'must not appear', ['rewrite'])];
  calls.alterResult = result => { expect(result.changes).toHaveLength(1); return { ...result, changes: [], file_operations: [], requires_host_commit: false }; };
  const suppressed = await apply(actions, ['context', 'rewrite'], 'suppressed'); expect(suppressed.isError).toBe(true); expect(JSON.stringify(suppressed)).toContain('PLAN_SELECTED_EFFECT_MISMATCH');
  calls.alterResult = undefined;
  const dependent = await apply(actions, ['selected'], 'cannot-borrow-publication'); expect(dependent.isError).toBe(true); expect(JSON.stringify(dependent)).toContain('POSTCONDITION_UNPROVABLE');
  expect(await readFile(path.join(workspace, 'left.txt'), 'utf8')).toBe('old left'); await expect(readFile(path.join(workspace, 'result.txt'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 60000);

test('multiple context publications follow admitted dependency order and their completed batch proves both members', () => fixture('legacy', async ({ workspace, apply }) => {
  const families = { 'data.json': 'auxiliaries', 'deprels.json': 'deprels', 'edeprels.json': 'edeprels', 'feats.json': 'features', 'tospace.json': 'expressions', 'udeprels.json': 'udeprels', 'upos.json': 'upos' };
  const base = Object.fromEntries(Object.keys(families).map(file => [file, sha256('base ' + file)])); calls.contextSha = sha256(JSON.stringify(base));
  const context = (id: string, depends_on: string[]) => {
    const files = Object.fromEntries(Object.entries(families).map(([file, family]) => [file, JSON.stringify({ [family]: { en: [id] } })]));
    const hashes = Object.fromEntries(Object.entries(files).map(([file, content]) => [file, sha256(content)]));
    return { id, type: 'prepare_context', language_code: 'en', files, file_hashes: hashes, base_hashes: base, context_sha256: sha256(JSON.stringify(hashes)), depends_on };
  };
  const first = context('first', ['prerequisite']), prerequisite = context('prerequisite', []), actions = [first, prerequisite, create('selected', 'result.txt', 'after both verified publications', ['first'])];
  const published = await apply(actions, ['first', 'prerequisite'], 'topological-contexts'); expect(published.isError, JSON.stringify(published)).not.toBe(true);
  const references = (published.structuredContent!.result as Record<string, unknown>).prepared_contexts as { action_id: string; context_sha256: string }[];
  expect(references.map(value => value.action_id)).toEqual(['prerequisite', 'first']); expect(references.map(value => value.context_sha256)).toEqual([prerequisite.context_sha256, first.context_sha256]);
  const dependent = await apply(actions, ['selected'], 'after-topological-contexts'); expect(dependent.isError, JSON.stringify(dependent)).not.toBe(true);
  expect((dependent.structuredContent!.result as Record<string, any>).details.satisfied_action_ids).toEqual(['prerequisite', 'first']); expect(await readFile(path.join(workspace, 'result.txt'), 'utf8')).toBe('after both verified publications');
}), 60000);
