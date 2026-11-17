/** Private, bounded persistent forward worker; imports never load weights. MIT. */
import path from 'node:path';
import { mkdirSync, readFileSync } from 'node:fs';
import { StringDecoder } from 'node:string_decoder';
import { startOwned } from './process.mjs';
import { assertOptIn, privateEnvironment, writeNew } from './preparation.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { writeCompressedObservation } from './study-observation.mjs';

const fail = code => Object.assign(new Error(code), { code });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const within = (root, selected) => selected === root || selected.startsWith(root + path.sep);

export function compareForwardResults(reference, instrumented, { maximum_absolute_error = 0.001, maximum_relative_scale = 0.001 } = {}) {
  const left = reference?.next_logits, right = instrumented?.next_logits;
  if (reference?.status !== 'observed' || instrumented?.status !== 'observed' || !Array.isArray(left) || !left.length || !Array.isArray(right) || left.length !== right.length ||
      left.some(value => !Number.isFinite(value)) || right.some(value => !Number.isFinite(value))) return { status: 'unverified', reason: 'FORWARD_PARITY_OBSERVATIONS_MISSING' };
  let maximum = 0, scale = 1, topLeft = 0, topRight = 0;
  for (let index = 0; index < left.length; index++) {
    maximum = Math.max(maximum, Math.abs(left[index] - right[index])); scale = Math.max(scale, Math.abs(left[index]));
    if (left[index] > left[topLeft]) topLeft = index;
    if (right[index] > right[topRight]) topRight = index;
  }
  const relative = maximum / scale;
  return { status: maximum <= maximum_absolute_error && relative <= maximum_relative_scale && topLeft === topRight ? 'passed' : 'failed',
    maximum_absolute_error: maximum, maximum_relative_scale: relative, top1_equal: topLeft === topRight, reference_top1: topLeft, instrumented_top1: topRight,
    compared_logits: left.length, thresholds: { maximum_absolute_error, maximum_relative_scale } };
}

export async function createForwardSupervisor(root, preparedModel, runtime, { directory, deadline, optIn, start = startOwned, environment = process.env, readyTimeoutMs = 120_000 } = {}) {
  assertOptIn({ optIn }, environment);
  if (!Number.isSafeInteger(deadline) || deadline <= Date.now() || !Number.isSafeInteger(readyTimeoutMs) || readyTimeoutMs < 1 || readyTimeoutMs > 120_000 ||
      !path.isAbsolute(directory ?? '') || !within(path.resolve(root, '.artifacts/local-evals'), path.resolve(directory)) ||
      preparedModel?.status !== 'prepared' || runtime?.status !== 'prepared' || !path.isAbsolute(preparedModel.directory ?? '') || !path.isAbsolute(runtime.python ?? '')) throw fail('FORWARD_SUPERVISOR_IDENTITY_REQUIRED');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const home = path.join(directory, 'home'); mkdirSync(home, { recursive: true, mode: 0o700 });
  const source = path.join(root, 'evals/local/study_forward.py');
  const env = { ...privateEnvironment(root, home), HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1' };
  const args = [source, '--opt-in', '--model', preparedModel.directory, '--artifact', preparedModel.artifact, '--maximum-forwards', '24'];
  const owned = start(runtime.python, args, { cwd: root, env, timeout: deadline - Date.now(), maximumBytes: 512 * 1024 ** 2, cancellationMs: 4750 });
  const decoder = new StringDecoder('utf8');
  let buffered = '', used = 0, pending, broken, stopped, ready = false;
  const frameLimit = 16 * 1024 ** 2;
  let resolveReady, rejectReady;
  const readiness = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const readyTimer = setTimeout(() => abort(fail('FORWARD_READY_TIMEOUT')), Math.min(readyTimeoutMs, deadline - Date.now()));

  async function stop(reason = 'forward-model-block-finished') {
    if (!stopped) stopped = (async () => {
      const started = Date.now(); clearTimeout(readyTimer);
      owned.child.stdin.end();
      const cooperative = await Promise.race([owned.done, pause(200).then(() => undefined)]);
      const outcome = cooperative ?? await owned.stop(reason);
      const elapsed = Date.now() - started;
      const { stdout, stderr, ...metadata } = outcome;
      const result = { ...metadata, stdout_bytes: Buffer.byteLength(stdout ?? ''), stdout_sha256: sha256(stdout ?? ''), stderr_bytes: Buffer.byteLength(stderr ?? ''), stderr_sha256: sha256(stderr ?? ''), output_retention: 'Full row documents are preserved as compressed evidence; worker stdout/stderr retain byte counts and digests only.', elapsed_ms: elapsed, cleanupVerified: outcome.cleanupVerified === true && elapsed <= 5000 };
      try { writeNew(path.join(directory, 'release.json'), result); }
      catch (error) { result.cleanupVerified = false; result.evidence_error = `FORWARD_RELEASE_EVIDENCE_FAILED:${error.code ?? error.message}`; }
      return result;
    })();
    return stopped;
  }
  function abort(error) {
    broken ??= error;
    clearTimeout(readyTimer); rejectReady(error);
    if (pending) { const selected = pending; pending = undefined; clearTimeout(selected.timer); selected.signal?.removeEventListener('abort', selected.abort); selected.reject(error); }
    void stop(error.code ?? 'forward-protocol-failed');
  }
  owned.done.then(outcome => {
    if (!stopped) abort(fail(`FORWARD_WORKER_EXITED:${outcome.error ?? outcome.stop_reason ?? outcome.code}`));
  });
  owned.child.stdout.on('data', bytes => {
    try {
    buffered += decoder.write(bytes);
    if (Buffer.byteLength(buffered) > frameLimit && !buffered.includes('\n')) { abort(fail('FORWARD_FRAME_TOO_LARGE')); return; }
    while (buffered.includes('\n')) {
      const boundary = buffered.indexOf('\n'), line = buffered.slice(0, boundary); buffered = buffered.slice(boundary + 1);
      if (Buffer.byteLength(line) > frameLimit) { abort(fail('FORWARD_FRAME_TOO_LARGE')); return; }
      if (!line.trim()) continue;
      let message;
      try { message = JSON.parse(line); } catch { if (!ready) continue; abort(fail('FORWARD_RESPONSE_INVALID')); return; }
      if (!ready) {
        if (message.event !== 'ready') continue;
        if (message.artifact !== preparedModel.artifact || message.maximum_forwards !== 24) { abort(fail('FORWARD_READY_IDENTITY_MISMATCH')); return; }
        ready = true; clearTimeout(readyTimer); writeNew(path.join(directory, 'ready.json'), { ...message, pid: owned.child.pid, command: runtime.python, args,
          adapter_sha256: sha256(readFileSync(source)), runtime_lock_sha256: runtime.lock_sha256 });
        resolveReady(message); continue;
      }
      if (!pending || !['observed', 'blocked'].includes(message.status)) { abort(fail('FORWARD_UNEXPECTED_RESPONSE')); return; }
      const selected = pending; pending = undefined; clearTimeout(selected.timer); selected.signal?.removeEventListener('abort', selected.abort);
      if (message.forward_ordinal !== used) { selected.reject(fail('FORWARD_ORDINAL_MISMATCH')); abort(fail('FORWARD_ORDINAL_MISMATCH')); return; }
      const file = path.join(directory, `forward-${String(used).padStart(2, '0')}.json.gz`);
      const document = { request: selected.request, response: message, received_at: new Date().toISOString() };
      try { const evidence = writeCompressedObservation(file, document); selected.resolve({ ...message, evidence }); }
      catch (error) { selected.reject(fail(`FORWARD_EVIDENCE_WRITE_FAILED:${error.code ?? error.message}`)); abort(fail('FORWARD_EVIDENCE_WRITE_FAILED')); return; }
    }
    } catch (error) { abort(fail(`FORWARD_PROTOCOL_OBSERVATION_FAILED:${error.code ?? error.message}`)); }
  });
  try { await readiness; } catch (error) { await stop(error.code); throw error; }
  return {
    pid: owned.child.pid, directory,
    async run(request, { deadline: requestDeadline = Math.min(deadline, Date.now() + 90_000), signal } = {}) {
      if (broken) throw broken;
      if (stopped) throw fail('FORWARD_WORKER_STOPPED');
      if (pending) throw fail('FORWARD_SINGLE_ACTIVE_REQUEST');
      if (used >= 24) throw fail('FORWARD_BUDGET_EXCEEDED');
      if (!Number.isSafeInteger(requestDeadline) || requestDeadline <= Date.now() || requestDeadline > deadline || requestDeadline - Date.now() > 90_000) throw fail('FORWARD_REQUEST_DEADLINE_INVALID');
      const payload = JSON.stringify(request) + '\n';
      if (Buffer.byteLength(payload) > 4 * 1024 ** 2) throw fail('FORWARD_REQUEST_TOO_LARGE');
      if (signal?.aborted) throw fail('FORWARD_REQUEST_CANCELLED');
      used++;
      try {
        return await new Promise((resolve, reject) => {
          const abortRequest = () => abort(fail('FORWARD_REQUEST_CANCELLED'));
          const timer = setTimeout(() => abort(fail('FORWARD_REQUEST_TIMEOUT')), requestDeadline - Date.now());
          pending = { request, resolve, reject, timer, signal, abort: abortRequest };
          signal?.addEventListener('abort', abortRequest, { once: true });
          owned.child.stdin.write(payload, error => { if (error) abort(fail('FORWARD_INPUT_CLOSED')); });
        });
      } catch (error) { const cleanup = await stop(error.code); error.cleanup = cleanup; throw error; }
    },
    stop,
    get used() { return used; },
  };
}
