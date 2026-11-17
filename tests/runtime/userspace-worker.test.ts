import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, realpath, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runUserspaceValidation } from '../../packages/coordinator/src/userspace-worker.js';

const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const selectedPython = await realpath(process.env.UD_AGENT_PYTHON ?? path.resolve(process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python'));
// Direct-worker fixtures exercise bootstrap/transport, independently of the
// selected test environment's Windows venv redirector and its nested Job.
// The explicit uv-venv case below still exercises the actual venv entrypoint.
const baseProbe = process.platform === 'win32' ? spawnSync(selectedPython, ['-I', '-c', 'import json,sys; print(json.dumps(sys._base_executable))'], { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 }) : undefined;
if (baseProbe && (baseProbe.error || baseProbe.status !== 0 || baseProbe.signal)) throw new Error(`Selected Python base discovery failed: ${baseProbe.error?.message ?? baseProbe.stderr}`);
const python = baseProbe ? await realpath(JSON.parse(baseProbe.stdout)) : selectedPython;

async function fixture(test: (runtime: { python: string; workerPath: string; upstreamPath: string; contextPath: string; bootstrap: string; guard: string }, root: string) => Promise<void>): Promise<void> {
  const base = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-worker-test-'));
  try {
    const real = await realpath(base); const root = path.join(real, 'workspace'); const worker = path.join(real, 'worker');
    await mkdir(root); await mkdir(path.join(worker, 'ud_agent'), { recursive: true });
    await writeFile(path.join(worker, 'ud_agent', '__init__.py'), '');
    for (const name of ['evidence.py', 'errors.py']) await copyFile(path.resolve('workers/ud/src/ud_agent', name), path.join(worker, 'ud_agent', name));
    await copyFile(path.resolve('workers/ud/src/ud_agent/contexts.py'), path.join(worker, 'ud_agent/contexts.py'));
    await copyFile(path.resolve('workers/ud/src/ud_agent/snapshot_receiver.py'), path.join(worker, 'ud_agent/snapshot_receiver.py'));
    await copyFile(path.resolve('workers/ud/src/ud_agent/unicode_paths.py'), path.join(worker, 'ud_agent/unicode_paths.py'));
    await copyFile(path.resolve('workers/ud/src/ud_agent/unicode_casefold.json'), path.join(worker, 'ud_agent/unicode_casefold.json'));
    await copyFile(path.resolve('workers/ud/src/ud_agent/userspace_operations.json'), path.join(worker, 'ud_agent/userspace_operations.json'));
    await writeFile(path.join(worker, 'ud_agent/wire.py'), `import json, pathlib, sys\nMAX_REQUEST_BYTES=16*1024*1024\ndef encode(value): return (json.dumps(value)+'\\n').encode()\ndef process(request):\n args=request['arguments']\n if args.get('options',{}).get('force_error'): return {'ok':False,'error':{'code':'INVALID_INPUT','message':'rejected'}}\n files=args.get('file_paths',[])\n return {'ok':True,'result':{'passed':False,'contents':[pathlib.Path(args['working_tree_path'],name).read_bytes().hex() for name in files],'root':args['working_tree_path'],'context':args['ud_context_path'],'python_prefix':sys.prefix}}\n`);
    await writeFile(path.join(root, 'a.conllu'), Buffer.from('# text = Ä\r\n1\tÄ\t_\tX\t_\t_\t0\troot\t_\t_\r\n'));
    const contextPath = path.join(real, 'context.json'); await writeFile(contextPath, '{}');
    await test({ python, workerPath: worker, upstreamPath: real, contextPath, bootstrap: path.resolve('workers/ud/src/ud_agent/userspace_bootstrap.py'), guard }, root);
  } finally { await rm(base, { recursive: true, force: true }); }
}

describe('verified snapshot userspace validation transport', () => {
  it('retains bounded worker refusal diagnostics while preserving the execution failure', async () => fixture(async (runtime, root) => {
    await writeFile(path.join(runtime.workerPath, 'ud_agent/wire.py'), 'import sys\nsys.stderr.write("discarded-prefix:"+"."*10000+"worker fixture refusal\\n")\nraise RuntimeError("worker fixture refusal")\n');
    const failure = await runUserspaceValidation(runtime, { operation: 'validation_report', arguments: { working_tree_path: root, file_paths: ['a.conllu'], ud_context_path: runtime.contextPath }, allowedRoots: [root] }).then(() => undefined, error => error);
    expect(failure?.message).toBe('WORKER_EXECUTION_FAILED');
    expect(failure?.cause).toBeInstanceOf(Error);
    expect(failure.cause.message).toContain('final 8192 retained; exit 1');
    expect(failure.cause.message).toContain('worker fixture refusal');
    expect(failure.cause.message).not.toContain('discarded-prefix');
    expect(failure.cause.message.length).toBeLessThan(8350);
  }));
  it('executes uv interpreter links with the private venv prefix and original snapshot bytes', async () => fixture(async (runtime, root) => {
    const environment = path.join(path.dirname(root), 'private-venv');
    const created = spawnSync('uv', ['--no-config', '--offline', '--cache-dir', path.join(path.dirname(root), 'uv-cache'), 'venv', '--python', runtime.python, '--no-python-downloads', environment], { encoding: 'utf8', cwd: path.dirname(root) });
    expect(created.status, created.stderr).toBe(0);
    const linkedRuntime = { ...runtime, python: path.join(environment, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python') };
    const inspected = spawnSync(linkedRuntime.python, ['-I', '-B', '-c', 'import json,sysconfig; print(json.dumps(sysconfig.get_path("purelib")))'], { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
    expect(inspected.error).toBeUndefined(); expect(inspected.status, inspected.stderr).toBe(0);
    const site = await realpath(JSON.parse(inspected.stdout)), relativeSite = path.relative(await realpath(environment), site);
    expect(path.isAbsolute(relativeSite) || relativeSite.split(path.sep).includes('..')).toBe(false);
    await writeFile(path.join(site, '_ud_venv_fixture.py'), 'value = "private venv dependency"\n');
    const wire = path.join(runtime.workerPath, 'ud_agent/wire.py');
    await writeFile(wire, (await readFile(wire, 'utf8')).replace('import json, pathlib, sys', 'import json, pathlib, sys\nfrom _ud_venv_fixture import value').replace("'python_prefix':sys.prefix", "'python_prefix':sys.prefix,'venv_dependency':value"));
    const original = await readFile(path.join(root, 'a.conllu'));
    const outcome = await runUserspaceValidation(linkedRuntime, { operation: 'validation_report', arguments: { working_tree_path: root, file_paths: ['a.conllu'], ud_context_path: runtime.contextPath }, allowedRoots: [root] });
    expect(outcome.result.python_prefix).toBe(await realpath(environment));
    expect(outcome.result.venv_dependency).toBe('private venv dependency');
    expect(outcome.memoryLimitEnforced).toBe(process.platform === 'linux' || process.platform === 'win32');
    expect(outcome.result.contents).toEqual([original.toString('hex')]);
    expect(await readFile(path.join(root, 'a.conllu'))).toEqual(original);
  }));
  it('runs an authorized custom context from its immutable snapshot with source mapping', async () => fixture(async (runtime, root) => {
    const context = path.join(path.dirname(root), 'custom'); await mkdir(context);
    const names = ['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'];
    const hash = (text: string) => createHash('sha256').update(text).digest('hex');
    const rules = Object.fromEntries(names.map(name => [name, hash('{}')]));
    for (const name of names) await writeFile(path.join(context, name), '{}');
    const manifest = path.join(context, 'context.json');
    await writeFile(manifest, JSON.stringify({ rule_dir: '.', rules, context_sha256: hash(JSON.stringify(rules)) }));
    const output = await runUserspaceValidation(runtime, { operation: 'validation_report', arguments: { working_tree_path: root, file_paths: ['a.conllu'], ud_context_path: manifest }, allowedRoots: [root, context] });
    expect(output.result.context).not.toBe(manifest);
    expect(output.snapshot.source_map.some(item => item.original_path === manifest)).toBe(true);
    expect(await readFile(path.join(context, 'data.json'), 'utf8')).toBe('{}');
  }), 30_000);

  it('runs a fresh fixed worker with exact snapshot bytes and separate context', async () => fixture(async (runtime, root) => {
    const request = { operation: 'validation_report' as const, arguments: { working_tree_path: root, file_paths: ['a.conllu'], ud_context_path: runtime.contextPath, options: { language_code: 'en' } }, allowedRoots: [root] };
    const original = await readFile(path.join(root, 'a.conllu'));
    const outcome = await runUserspaceValidation(runtime, request);
    expect(outcome.result.passed).toBe(false);
    expect(outcome.result.contents).toEqual([original.toString('hex')]);
    expect(outcome.result.root).not.toBe(root);
    expect(outcome.result.context).toBe(runtime.contextPath);
    expect(outcome.snapshot.files.map(file => file.path)).toEqual(['a.conllu']);
    expect(outcome.isolation).toBe('userspace');
    expect(await readFile(path.join(root, 'a.conllu'))).toEqual(original);
    expect(await readdir(root)).toEqual(['a.conllu']);
  }));

  it('selects the complete captured CoNLL-U inventory only for the CLI convenience path', async () => fixture(async (runtime, root) => {
    await writeFile(path.join(root, 'b.conllu'), 'second\n');
    const request = { operation: 'validation_report' as const, arguments: { working_tree_path: root, file_paths: [], ud_context_path: runtime.contextPath }, allowedRoots: [root] };
    await expect(runUserspaceValidation(runtime, request)).rejects.toThrow('distinct snapshot files');
    const output = await runUserspaceValidation(runtime, { ...request, selectAllFiles: true });
    expect(output.result.contents).toEqual([(await readFile(path.join(root, 'a.conllu'))).toString('hex'), Buffer.from('second\n').toString('hex')]);
    expect(request.arguments.file_paths).toEqual([]);
  }));

  it('rejects ungranted paths, unverified contexts, duplicates and project code', async () => fixture(async (runtime, root) => {
    const request = { operation: 'validation_report' as const, arguments: { working_tree_path: root, file_paths: ['a.conllu'], ud_context_path: runtime.contextPath }, allowedRoots: [root] };
    await expect(runUserspaceValidation(runtime, { ...request, allowedRoots: [] })).rejects.toThrow('authorized roots');
    const untrusted = path.join(path.dirname(root), 'untrusted-context.json'); await writeFile(untrusted, '{}');
    await expect(runUserspaceValidation(runtime, { ...request, arguments: { ...request.arguments, ud_context_path: untrusted } })).rejects.toThrow('authorized roots');
    await expect(runUserspaceValidation(runtime, { ...request, arguments: { ...request.arguments, file_paths: ['a.conllu', 'a.conllu'] } })).rejects.toThrow('distinct snapshot files');
    await expect(runUserspaceValidation(runtime, { ...request, operation: 'project_consistency_report' as 'validation_report' })).rejects.toThrow('Unsupported userspace operation');
  }));

  it('propagates stable worker errors and rejects pre-cancelled requests', async () => fixture(async (runtime, root) => {
    const request = { operation: 'validation_report' as const, arguments: { working_tree_path: root, file_paths: ['a.conllu'], ud_context_path: runtime.contextPath, options: { force_error: true } }, allowedRoots: [root] };
    await expect(runUserspaceValidation(runtime, request)).rejects.toMatchObject({ code: 'INVALID_INPUT', message: 'rejected' });
    const controller = new AbortController(); controller.abort();
    await expect(runUserspaceValidation(runtime, { ...request, signal: controller.signal })).rejects.toThrow('WORKER_CANCELLED');
  }));

  it('executes a real snapshot-confined analysis operation without host exports', async () => fixture(async (runtime, root) => {
    const request = { operation: 'treebank_profile', arguments: { working_tree_path: root, file_paths: ['a.conllu'], ud_context_path: runtime.contextPath }, allowedRoots: [root] };
    const realWorker = { ...runtime, workerPath: path.resolve('workers/ud/src') };
    const outcome = await runUserspaceValidation(realWorker, request);
    expect(outcome.result).toMatchObject({ sentence_count: 1, word_count: 1, scope: ['a.conllu'] });
    expect(await readdir(root)).toEqual(['a.conllu']);
  }));
});
