import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdtemp, open, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { captureOperationSnapshot } from '../../workspace/src/input-broker.js';
import type { ContextBundle } from '../../workspace/src/input-broker.js';
import { streamVerifiedSnapshot } from '../../workspace/src/snapshot-transfer.js';
import { encodeSnapshotFrames } from '../../workspace/src/snapshot-wire.js';
import { USERSPACE_READ_ONLY_OPERATIONS } from '../../workspace/src/userspace-operations.js';
import { resolveWindowsPython } from './windows-python.js';

/** Inputs must come from a verified, process-owned runtime capability. */
export type UserspaceWorkerRuntime = {
  python: string; workerPath: string; upstreamPath: string; contextPath: string; bootstrap: string; guard: string; perl?: string; perlLibraryPaths?: readonly string[]; perlLoader?: Readonly<{ executable: string; libraryPaths: readonly string[] }>; renderManifest?: string; contextAssetRoot?: string;
};
export type UserspaceValidation = {
  operation: string;
  contextBundle?: ContextBundle;
  arguments: Record<string, unknown>;
  allowedRoots: readonly string[];
  /** Internal CLI convenience: select the complete captured CoNLL-U inventory. */
  selectAllFiles?: boolean;
  signal?: AbortSignal;
};
export type UserspaceValidationOutcome = {
  result: Record<string, unknown>;
  snapshot: { root_identity?: { device: string; inode: string }; sha256: string; files: { path: string; size: number; sha256: string }[]; source_map: { snapshot_path: string; original_path: string }[] };
  isolation: 'userspace';
  memoryLimitEnforced: boolean;
};

function safeEnvironment(home: string): NodeJS.ProcessEnv {
  return process.platform === 'win32'
    ? { PATH: `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32`, SystemRoot: process.env.SystemRoot ?? 'C:\\Windows', HOME: home, USERPROFILE: home, TEMP: home, TMP: home, LANG: 'C.UTF-8' }
    : { PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
}

async function runtimeFileHash(filename: string, interpreter = false): Promise<string> {
  // uv deliberately links the venv interpreter to its verified base Python.
  // Hash the resolved target; the Linux supervisor pins and hashes that same
  // executable descriptor while preserving the original venv path as argv[0].
  const canonical = interpreter && process.platform === 'linux' ? await realpath(filename) : filename;
  const file = await open(canonical, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size > 256n * 1024n * 1024n) throw new Error('WORKER_RUNTIME_IDENTITY_INVALID');
    const hash = createHash('sha256'); const bytes = Buffer.alloc(1024 * 1024); let total = 0;
    for (;;) { const part = await file.read(bytes, 0, bytes.length, total); if (!part.bytesRead) break; total += part.bytesRead; if (BigInt(total) > before.size) throw new Error('WORKER_RUNTIME_IDENTITY_CHANGED'); hash.update(bytes.subarray(0, part.bytesRead)); }
    const after = await file.stat({ bigint: true });
    if (BigInt(total) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('WORKER_RUNTIME_IDENTITY_CHANGED');
    if (interpreter && process.platform === 'linux' && await realpath(filename) !== canonical) throw new Error('WORKER_RUNTIME_IDENTITY_CHANGED');
    return hash.digest('hex');
  } finally { await file.close(); }
}

/** Run only the fixed read-only validation workers, using a verified snapshot. */
export async function runUserspaceValidation(runtime: UserspaceWorkerRuntime, input: UserspaceValidation): Promise<UserspaceValidationOutcome> {
  if ([runtime.python, runtime.workerPath, runtime.upstreamPath, runtime.contextPath, runtime.bootstrap, runtime.guard].some(value => typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0'))) throw new Error('Invalid verified userspace runtime.');
  if (!USERSPACE_READ_ONLY_OPERATIONS.includes(input.operation)) throw new Error('Unsupported userspace operation.');
  if (!input.arguments || typeof input.arguments !== 'object' || Array.isArray(input.arguments)) throw new Error('Invalid worker arguments.');
  const root = input.arguments.working_tree_path;
  if (typeof root !== 'string' || !path.isAbsolute(root)) throw new Error('A granted absolute working tree is required.');
  if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
  const producer = new AbortController();
  const signal = input.signal ? AbortSignal.any([input.signal, producer.signal]) : producer.signal;
  const captured = await captureOperationSnapshot(runtime.guard, input.arguments, input.allowedRoots, signal, runtime.contextPath, input.operation, input.contextBundle);
  const snapshot = captured.snapshot;
  try {
    const args = { ...captured.arguments };
    if (input.operation === 'validation_report') {
      if (input.selectAllFiles) args.file_paths = snapshot.files.filter(file => file.path.endsWith('.conllu')).map(file => file.path);
      const files = args.file_paths;
      const available = new Set(snapshot.files.map(file => file.path));
      if (!Array.isArray(files) || files.length === 0 || files.length > 10_000 || files.some(file => typeof file !== 'string' || !available.has(file)) || new Set(files).size !== files.length) throw new Error('Selected files must identify distinct snapshot files.');
    }
    const staging = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-worker-stage-'));
    try {
      const stageRoot = await realpath(staging);
      const request = Buffer.from(`${JSON.stringify({ operation: input.operation, arguments: args, ...(captured.brokerEvidence ? { broker_evidence: captured.brokerEvidence } : {}) })}\n`, 'utf8');
      if (request.length > 16 * 1024 * 1024) throw new Error('WORKER_REQUEST_TOO_LARGE');
      const response = await runWorker(runtime, snapshot.sha256, stageRoot, request, streamVerifiedSnapshot(runtime.guard, snapshot, signal), signal, () => producer.abort());
      if (!response || typeof response !== 'object' || Array.isArray(response)) throw new Error('WORKER_RESPONSE_INVALID');
      const value = response as Record<string, unknown>;
      if (value.ok === false) {
        const error = value.error;
        if (!error || typeof error !== 'object' || Array.isArray(error) || typeof (error as Record<string, unknown>).code !== 'string' || typeof (error as Record<string, unknown>).message !== 'string') throw new Error('WORKER_RESPONSE_INVALID');
        const details = error as { code: string; message: string };
        const failure = new Error(details.message) as Error & { code: string };
        failure.code = details.code;
        throw failure;
      }
      if (value.ok !== true || !value.result || typeof value.result !== 'object' || Array.isArray(value.result)) throw new Error('WORKER_RESPONSE_INVALID');
      return { result: value.result as Record<string, unknown>, snapshot: { root_identity: snapshot.root_identity, sha256: snapshot.sha256, files: snapshot.files, source_map: captured.sourceMap }, isolation: 'userspace', memoryLimitEnforced: process.platform === 'linux' || process.platform === 'win32' };
    } finally { await rm(staging, { recursive: true, force: true }); }
  } finally { producer.abort(); await snapshot.cleanup(); }
}

async function runWorker(runtime: UserspaceWorkerRuntime, expected: string, staging: string, request: Buffer, frames: ReturnType<typeof streamVerifiedSnapshot>, signal: AbortSignal | undefined, cancelProducer: () => void): Promise<unknown> {
  const windows = process.platform === 'win32';
  const supervised = windows || process.platform === 'linux';
  const windowsPython = windows ? await resolveWindowsPython(runtime.python) : undefined;
  const python = windowsPython?.executable ?? runtime.python;
  const hashes = supervised ? await Promise.all([windowsPython?.executableSha256 ?? runtimeFileHash(python, true), runtimeFileHash(runtime.bootstrap)]) : [];
  const executable = supervised ? runtime.guard : runtime.python;
  const venv = windowsPython?.venv;
  const argv = supervised ? ['contained-run', '--executable', python, '--executable-sha256', hashes[0]!, '--bootstrap', runtime.bootstrap, '--bootstrap-sha256', hashes[1]!, '--worker', runtime.workerPath, '--upstream', runtime.upstreamPath, '--context', runtime.contextPath, '--snapshot-sha256', expected, '--staging', staging,
    ...(venv ? ['--venv-executable', venv.executable, '--venv-executable-sha256', venv.executableSha256, '--venv-config', venv.config, '--venv-config-sha256', venv.configSha256] : [])]
    : ['-I', '-B', runtime.bootstrap, runtime.workerPath, runtime.upstreamPath, runtime.contextPath, expected, staging];
  return new Promise((resolve, reject) => {
    // -I ignores PYTHON* environment variables, so -B explicitly prevents
    // bytecode writes from invalidating the verified shared environment.
    const child = spawn(executable, argv, {
      shell: false, detached: !windows, windowsHide: true, cwd: staging, env: { ...safeEnvironment(staging), ...(venv ? { __PYVENV_LAUNCHER__: venv.executable } : {}), ...(runtime.perl ? { UD_AGENT_PERL: runtime.perl, UD_AGENT_PERL_LIB_PATHS: JSON.stringify(runtime.perlLibraryPaths ?? []) } : {}), ...(runtime.perlLoader ? { UD_AGENT_PERL_LOADER: runtime.perlLoader.executable, UD_AGENT_PERL_LOADER_LIB_PATHS: JSON.stringify(runtime.perlLoader.libraryPaths) } : {}), ...(runtime.renderManifest ? { UD_AGENT_RENDER_MANIFEST: runtime.renderManifest } : {}), ...(runtime.contextAssetRoot ? { UD_AGENT_CONTEXT_ASSET_ROOT: runtime.contextAssetRoot } : {}), UD_AGENT_UDTOOLS: runtime.upstreamPath }, stdio: windows ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = []; let stdoutSize = 0; let stderrSize = 0; let stderrDiagnostic = Buffer.alloc(0); let failure: Error | undefined; let transferDone = false; let closeCode: number | null | undefined; let forced: ReturnType<typeof setTimeout> | undefined;
    let stopping = false; let settled = false;
    const stop = (error: Error) => {
      if (settled) return;
      failure ??= error;
      if (stopping) return; stopping = true;
      // Destroying a stream cannot interrupt an async generator's pending
      // guarded read. Revoke the producer's own signal before waiting for it.
      cancelProducer();
      if (closeCode !== undefined || child.exitCode !== null || child.signalCode !== null) return;
      if (windows) child.kill('SIGKILL');
      else if (supervised) { child.kill('SIGTERM'); forced ??= setTimeout(() => child.kill('SIGKILL'), 35000); }
      else if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }
    };
    const timer = setTimeout(() => stop(new Error('WORKER_TIMEOUT')), 300_000);
    const aborted = () => stop(new Error('WORKER_CANCELLED'));
    signal?.addEventListener('abort', aborted, { once: true });
    if (signal?.aborted) aborted();
    // Pipes can report a late reset when a refusing worker exits without
    // reading its inputs. Own those errors for the entire stream lifetime,
    // including after the transfer pipeline has settled.
    const pipeFailed = (error: Error) => stop(new Error('WORKER_EXECUTION_FAILED', { cause: error }));
    child.stdout!.on('error', pipeFailed);
    child.stderr!.on('error', pipeFailed);
    child.stdout!.on('data', (chunk: Buffer) => { stdoutSize += chunk.length; if (stdoutSize > 32 * 1024 * 1024) stop(new Error('WORKER_OUTPUT_TOO_LARGE')); else stdout.push(chunk); });
    child.stderr!.on('data', (chunk: Buffer) => { stderrSize += chunk.length; stderrDiagnostic = Buffer.from(Buffer.concat([stderrDiagnostic, chunk]).subarray(-8192)); if (stderrSize > 1024 * 1024) stop(new Error('WORKER_OUTPUT_TOO_LARGE')); });
    child.stdin!.on('error', error => { if ((error as NodeJS.ErrnoException).code !== 'EPIPE') pipeFailed(error); });
    child.once('error', error => stop(error));
    const finish = () => {
      if (settled || closeCode === undefined || !transferDone) return;
      settled = true;
      clearTimeout(timer); clearTimeout(forced); signal?.removeEventListener('abort', aborted);
      if (closeCode !== 0) failure ??= new Error('WORKER_EXECUTION_FAILED');
      if (failure) {
        if (stderrDiagnostic.length) failure.cause = new Error(`Userspace worker stderr (${stderrSize} bytes; final ${stderrDiagnostic.length} retained; exit ${closeCode}): ${stderrDiagnostic.toString('utf8')}`, { cause: failure.cause });
        return reject(failure);
      }
      try {
        const bytes = Buffer.concat(stdout);
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        if (!text.endsWith('\n') || text.slice(0, -1).includes('\n')) throw new Error('invalid stream');
        resolve(JSON.parse(text.slice(0, -1)) as unknown);
      } catch { reject(new Error('WORKER_RESPONSE_INVALID')); }
    };
    const transfer = windows ? child.stdin : child.stdio[3];
    if (!(transfer instanceof Writable)) { transferDone = true; stop(new Error('WORKER_TRANSFER_UNAVAILABLE')); }
    else {
      transfer.on('error', pipeFailed);
      const encoded = async function* () { yield* encodeSnapshotFrames(frames); if (windows) yield request; };
      void pipeline(Readable.from(encoded()), transfer).then(() => { transferDone = true; finish(); }, error => { transferDone = true; stop(error instanceof Error ? error : new Error('WORKER_TRANSFER_FAILED')); finish(); });
    }
    if (!windows) child.stdin!.end(request);
    // A successful interpreter exit also revokes its ordinary process group.
    // Windows and Linux perform the stronger native job/subreaper cleanup.
    child.once('exit', (code) => {
      if (code !== 0) stop(new Error(code === 124 && windows ? 'WORKER_TIMEOUT' : 'WORKER_EXECUTION_FAILED')); if (!supervised && child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group is already absent */ } } });
    child.once('close', code => { closeCode = code; if (code !== 0 && !failure) failure = new Error(code === 124 && windows ? 'WORKER_TIMEOUT' : 'WORKER_EXECUTION_FAILED'); finish(); });
  });
}
