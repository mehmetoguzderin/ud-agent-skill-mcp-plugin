/** Campaign-owned POSIX process-group supervision. MIT. */
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { StringDecoder } from 'node:string_decoder';

const delay = (milliseconds) => new Promise(resolve => setTimeout(resolve, milliseconds));

/** EPERM is failed signal-query evidence, never proof that a group exists or is
 * gone. For a caller's detached owned group, a complete process table independently
 * proves absence or continuing presence of members under the same owner UID.
 */
export function inspectOwnedProcessGroup(pgid, { probe = process.kill.bind(process), table = options => spawnSync('/bin/ps', ['-axo', 'pgid=,pid=,uid='], options), timeout = 1000 } = {}) {
  if (!Number.isSafeInteger(pgid) || pgid < 1 || !Number.isSafeInteger(timeout) || timeout < 1) throw new Error('OWNED_PROCESS_IDENTITY_INVALID');
  const evidence = [];
  try { probe(-pgid, 0); return { state: 'present', evidence: [{ method: 'signal-zero', pgid, outcome: 'present' }] }; }
  catch (error) {
    evidence.push({ method: 'signal-zero', pgid, outcome: 'failed', code: error.code ?? 'UNKNOWN', message: error.message });
    if (error.code === 'ESRCH') return { state: 'absent', evidence };
    if (error.code !== 'EPERM') return { state: 'unverified', evidence };
  }
  let result;
  try { result = table({ encoding: 'utf8', timeout: Math.min(timeout, 1000), maxBuffer: 8 * 1024 ** 2, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } }); }
  catch (error) { evidence.push({ method: 'process-table', outcome: 'failed', code: error.code ?? 'UNKNOWN', message: error.message }); return { state: 'unverified', evidence }; }
  const observation = { method: 'process-table', command: '/bin/ps', arguments: ['-axo', 'pgid=,pid=,uid='], status: result.status, signal: result.signal ?? null,
    ...(result.error ? { error: { code: result.error.code ?? 'UNKNOWN', message: result.error.message } } : {}), stderr: String(result.stderr ?? '') };
  if (result.error || result.status !== 0 || result.signal || typeof result.stdout !== 'string') {
    evidence.push({ ...observation, outcome: 'failed' }); return { state: 'unverified', evidence };
  }
  const rows = [], seen = new Set();
  for (const line of result.stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    // Darwin prints uid_t values such as nobody as signed -2. Retain that
    // numeric observation rather than rejecting an otherwise complete table.
    const match = /^\s*(\d+)\s+(\d+)\s+(-?\d+)\s*$/.exec(line);
    const values = match?.slice(1).map(Number);
    if (!values || values.some(value => !Number.isSafeInteger(value)) || values[0] < 0 || values[0] > 0x7fffffff || values[1] > 0x7fffffff || values[2] < -0x80000000 || values[2] > 0xffffffff || values[1] < 1 || seen.has(values[1])) {
      evidence.push({ ...observation, outcome: 'failed', reason: 'PROCESS_TABLE_INVALID', stdout: result.stdout }); return { state: 'unverified', evidence };
    }
    seen.add(values[1]); rows.push({ pgid: values[0], pid: values[1], uid: values[2] });
  }
  // A successful command with empty, truncated, or filtered output is not an
  // absence observation. Require the observer itself in the process inventory.
  if (!rows.some(row => row.pid === process.pid && (typeof process.getuid !== 'function' || row.uid === process.getuid()))) {
    evidence.push({ ...observation, outcome: 'failed', reason: 'PROCESS_TABLE_OBSERVER_MISSING', rows }); return { state: 'unverified', evidence };
  }
  const matching = rows.filter(row => row.pgid === pgid);
  const ownedUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  const sameOwner = ownedUid !== undefined && matching.every(row => (row.uid < 0 ? row.uid + 0x100000000 : row.uid) === ownedUid);
  evidence.push({ ...observation, outcome: matching.length ? 'present' : 'absent', rows, matching, same_owner: sameOwner });
  return { state: !matching.length ? 'absent' : sameOwner ? 'present' : 'unverified', evidence };
}

/** done includes reconciliation of the parent and its owned group.
 * cleanupVerified:false blocks further model loads or episodes.
 */
export function startOwned(command, args, { cwd, env, log, signal, timeout = 90_000, maximumBytes = 8 * 1024 ** 2, cancellationMs = 5_000 } = {}) {
  if (process.platform === 'win32') throw new Error('OWNED_PROCESS_GROUP_UNSUPPORTED');
  if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 2_147_483_647 || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || !Number.isSafeInteger(cancellationMs) || cancellationMs < 50 || cancellationMs > 5_000) throw new Error('OWNED_PROCESS_LIMIT_INVALID');
  const child = spawn(command, args, { cwd, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const decoders = { stdout: new StringDecoder('utf8'), stderr: new StringDecoder('utf8') };
  let output = '', errorOutput = '', bytes = 0, stopped, timer, closing, exited = false, closed = false;
  let code = null, termination, spawnError, groupGone = false, resolveDone, resolveExit, resolveClose;
  const cleanupEvidence = [];
  const done = new Promise(resolve => { resolveDone = resolve; });
  const exit = new Promise(resolve => { resolveExit = resolve; });
  const close = new Promise(resolve => { resolveClose = resolve; });
  const abort = () => { void stop(String(signal.reason ?? 'cancelled')); };

  function groupExists(deadline) {
    if (groupGone || !child.pid) return false;
    const observation = inspectOwnedProcessGroup(child.pid, { timeout: Math.max(1, deadline - Date.now()) });
    cleanupEvidence.push(...observation.evidence);
    if (observation.state === 'absent') { groupGone = true; return false; }
    if (observation.state === 'unverified') throw new Error('Owned process group absence remains unverified; signal query or independent process inventory failed.');
    return true;
  }
  function send(sig, deadline) {
    if (groupGone || !child.pid) return;
    try { process.kill(-child.pid, sig); }
    catch (error) {
      cleanupEvidence.push({ method: 'signal', pgid: child.pid, signal: sig, outcome: 'failed', code: error.code ?? 'UNKNOWN', message: error.message });
      if (error.code === 'ESRCH') groupGone = true;
      else if (error.code !== 'EPERM') throw error;
      else {
        // The signal remains denied. An independent owned-group observation
        // permits bounded waiting for an already progressing graceful exit;
        // it does not turn the failed signal into a successful cancellation.
        groupExists(deadline);
      }
    }
  }
  async function waitForGroup(deadline) {
    while (groupExists(deadline)) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) return false;
      await delay(Math.min(20, remaining));
    }
    return true;
  }
  async function reconcile() {
    const deadline = Date.now() + cancellationMs;
    let cleanupVerified = false, cleanupError;
    try {
      if (!child.pid) { await exit; cleanupVerified = true; }
      else if (!groupExists(deadline)) cleanupVerified = true;
      else {
        send('SIGTERM', deadline);
        // Keep a portion of the grace for SIGKILL and observed disappearance.
        cleanupVerified = await waitForGroup(deadline - Math.max(25, Math.ceil(cancellationMs / 5)));
        if (!cleanupVerified) { send('SIGKILL', deadline); cleanupVerified = await waitForGroup(deadline); }
      }
    } catch (error) { cleanupError = error.message; }
    if (cleanupVerified && Date.now() > deadline) { cleanupVerified = false; cleanupError = 'Owned process absence was not verified within cancellation grace.'; }
    if (!cleanupVerified) cleanupError ??= 'Owned process group still exists after cancellation grace.';
    if (cleanupVerified && !exited) {
      await Promise.race([exit, delay(Math.max(0, deadline - Date.now()))]);
      if (!exited) { cleanupVerified = false; cleanupError = 'Owned parent exit was not observed.'; }
    }
    if (exited && !closed) await Promise.race([close, delay(Math.min(50, Math.max(0, deadline - Date.now())))]);
    // A process outside this group holding a pipe cannot extend the grace.
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    if (!closed) { output += decoders.stdout.end(); errorOutput += decoders.stderr.end(); }
    clearTimeout(timer); signal?.removeEventListener('abort', abort);
    const result = { code, signal: termination, stdout: output, stderr: errorOutput, cleanupVerified, cleanup_evidence: cleanupEvidence,
      ...(stopped ? { stop_reason: stopped } : {}), ...(spawnError ? { error: spawnError.message } : {}), ...(cleanupError ? { cleanup_error: cleanupError } : {}) };
    resolveDone(result);
    return result;
  }
  function stop(reason = 'cancelled') {
    if (!closing) { stopped ??= reason; closing = reconcile(); }
    return done;
  }
  const consume = channel => data => {
    bytes += data.length;
    if (bytes > maximumBytes) { void stop('process-output-budget'); return; }
    if (log) {
      try { appendFileSync(log, data, { mode: 0o600 }); }
      catch (error) { spawnError = error; void stop('process-log-failed'); return; }
    }
    const text = decoders[channel].write(data);
    if (channel === 'stdout') output += text; else errorOutput += text;
  };
  child.stdout.on('data', consume('stdout')); child.stderr.on('data', consume('stderr'));
  child.stdin.on('error', () => { /* Parent exit may close stdin before end(). */ });
  child.once('error', error => {
    spawnError = error; exited = true; resolveExit();
    if (!closing) closing = reconcile();
  });
  child.once('exit', (exitCode, exitSignal) => {
    code = exitCode; termination = exitSignal; exited = true; resolveExit();
    if (!closing) closing = reconcile();
  });
  child.once('close', () => {
    closed = true; output += decoders.stdout.end(); errorOutput += decoders.stderr.end(); resolveClose();
  });
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  if (timeout) timer = setTimeout(() => { void stop('timed-out'); }, timeout);
  return { child, done, stop };
}

export async function runOwned(command, args, options) {
  const owned = startOwned(command, args, options); owned.child.stdin.end();
  const result = await owned.done;
  if (result.code !== 0 || result.cleanupVerified !== true || result.stop_reason) throw Object.assign(new Error(`${command}: ${result.cleanup_error ?? result.error ?? result.stop_reason ?? (result.stderr.slice(-1500) || `exit ${result.code}`)}`), { result });
  return result;
}
